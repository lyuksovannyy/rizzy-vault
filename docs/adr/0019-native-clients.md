# ADR 0019: Native desktop and mobile clients in separate repositories

- Status: Accepted
- Date: 2026-09-27
- Deciders: project owner
- Milestone: M3 (desktop) / M7 (mobile)
- Supersedes: [ADR 0015](0015-desktop-tauri.md) in full; [ADR 0013](0013-shared-client-core.md) (Milestone line, Context in part, §1 in part, §2 in part, §3 in part, §5, §6 in part, Negative in part, Risks in part); [ADR 0016](0016-workspace-layout.md) (§3 in part, R2 in part, R5, R6, R7 in part, §5 in part, §7, Risks in part, Alternatives considered in part); [ADR 0009](0009-crypto-dependency-policy.md) ("RNG rules" in part). §1 lists the parts, under [ADR 0020](0020-partial-supersession.md) point 9 (owner decision 6).
- Depends on: [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession; Accepted)

## Context

### What the owner decided on 2026-09-26

The full text is under [Owner decisions](#owner-decisions-2026-09-26). In short:
- The web platforms stay in this repository ([ADR 0014](0014-ui-stack.md)).
- Desktop and mobile clients are native: WinUI 3 with C# (Windows), Qt 6 Quick/QML (Linux, chosen over GTK for control of the look), SwiftUI (macOS and iOS), Kotlin (Android). This reverses ADR 0014 answer 3, recorded earlier the same day, and replaces Accepted ADR 0015 (Tauri).
- One repository per platform toolchain: `rizzy-vault-apple`, `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`.
- One Rust core in this repository reaches every native client through generated bindings. No per-platform security core. For now, no hand-written C ABI with an `unsafe` exception, and no out-of-process core as the default. The C# and C++ generator routes are spiked first. If a spike fails, the question returns to the owner.
- [ADR 0017](0017-licensing.md) stays deferred.
- This ADR changes ADR 0013 and ADR 0016 by partial supersession: it names the parts it replaces, and the rest of each stays binding. [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession), a small successor to ADR 0001, adds that status (open question 1, answered).

Nothing in M1 or M2 changes in product scope: `rizzy-client`, `rizzy-wasm`, `rv`, the web vault and the extensions are as before. One finding does reach M1: the generated-glue `unsafe` described below applies to `rizzy-wasm` today (open question 2).

### What it collides with

| Document | Status | Conflict |
|---|---|---|
| ADR 0013 | Accepted | Milestone line "M3 (Tauri)". Context: "In Tauri and on mobile it is a process or language boundary". §1: `rizzy-desktop` links `rizzy-client` "with no FFI"; `rizzy-ffi` serves Android and iOS only, from M7. §2: the desktop column assumes a Rust host process. §3: the FFI rules name `rizzy-wasm`, `rizzy-ffi` and the Tauri IPC commands; rule 7 names wasm-bindgen and UniFFI as the only generators. §5 and §6: Kotlin and Swift only. Negative: "Two binding generators". Risks: "an upgrade that brings in `unsafe` fails in its own PR" (not true, below), and a C ABI fallback |
| ADR 0015 | Accepted | All of it. It rejected native UI per OS as "impossible at our size" |
| ADR 0016 | Accepted | `rizzy-desktop` (Tauri, M3) in §3, R2, R5, R6 and the cargo-deny wrappers; `rizzy-ffi` at M7 in §3 and R5. R7 and §5 rest on "generated glue compiles under `forbid`" meaning "has no `unsafe`". §7 puts `apps/desktop`, `apps/android` and `apps/ios` in this repository and adds `apps/desktop/src-tauri` to the workspace in M3. Risks: the Tauri crate's GUI dependencies. "Separate repositories per component" is a rejected alternative |
| ADR 0009 | Accepted | "RNG rules", third bullet, lists the crate kinds that depend on getrandom directly: "CLI, server, Tauri shell, UniFFI bindings, wasm bindings". A binding crate from another generator is none of them (§1.3). Owner decision 1 names `rizzy-desktop` |
| ADR 0014 | Proposed | Answer 3 (desktop reuses `apps/web`). Revised in the same change: it now covers the web platforms and leaves desktop to the desktop ADR (ADR 0015 while it binds), so it holds whether this ADR is accepted or not |
| ADR 0017 | Proposed | Decision 1 covers "this repository" and names the "desktop shell". Its Context names "Desktop releases (Tauri)" and "natively in desktop (ADR 0015)"; its App Store rows are keyed to M7. Decision 5 bans third-party LGPL, which Qt is, and names licence gates for JS, Swift and Kotlin only, the Swift and Kotlin ones in M7. Decision 6's SPDX list has no C#, C++, QML or XAML |
| ADRs 0002, 0004, 0007 | Accepted | None as drafted. §8's readers-before-writers rule is a recommendation for later changes to them, not a change made here |
| [ROADMAP](../ROADMAP.md) | – | §3 M3 and M7 rows; the §4.1 crate list (`rizzy-desktop`); §4.3 "Unlock with biometrics / OS keychain on desktop & mobile" (Windows, §2.1); §4.5 "component library shared by web vault + extension + desktop" and "Desktop app (recommendation: **Tauri** …)"; §5 rows Client core, UI stack and Desktop |
| [THREAT_MODEL](../THREAT_MODEL.md) | – | §3.1 Desktop row; the §3.2 diagram ("desktop Tauri"); TB-10 (a process boundary "in Tauri and mobile"); §7.3 is written for a webview and its heading names Tauri (ADR 0015 links that anchor); A9 and INV-57 do not cover Swift, Gradle, NuGet, C++ or their toolchains; A14 defers Tauri's screen-capture support to M3; AST-22 and the §8.10 traceability row cite ADR 0015 §9; INV-35's mechanism is a sandboxed iframe; INV-55 assumed one updater; INV-60 was written for Rust binaries, and AR-10 says crash dumps "are disabled"; INV-64 assumes the provider sets `clientDataJSON` and covers only "extension or mobile"; INV-68 has no wording for native desktops |
| [CRYPTO.md](../CRYPTO.md) | – | §1 goal 6 names only UniFFI and TypeScript, Kotlin and Swift; the §4.2 keystore-unlock row cites ADR 0015; §12.1's platform-crate list names the Tauri shell and only UniFFI bindings; §12.2's Limits do not name binding glue; §15 item 8 names only Kotlin and Swift |

Accepted ADRs are immutable. [ADR 0001](0001-record-architecture-decisions.md) point 4 and the [README](README.md#lifecycle) allow status, typo and link fixes, and amendments an ADR itself provides for. Neither ADR 0013 nor ADR 0016 provides for these changes. ADR 0001 point 3 knows only full supersession. So the owner chose partial supersession through ADR 0020 (owner decision 6), and this ADR only proposes. No native-client code, binding crate or client repository is created before the owner accepts it (the ADR-first rule).

### Requirements

- [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3), Must, M3: the design system; a desktop app; quick access on a global hotkey; accessibility (keyboard-only use, screen-reader labels, WCAG AA contrast).
- [ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7), Must, M7: an Android app with Autofill Framework integration; an iOS app with an AutoFill Credential Provider; "Shared Rust core via **UniFFI** bindings (no crypto re-implemented in Kotlin/Swift)"; biometric unlock. Should: a passkey provider on Android 14+ and iOS 17+.
- [ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Should, M3: unlock with biometrics or the OS keychain. [§4.4](../ROADMAP.md#44-url-matching--autofill-m2), Should, M3: a Safari extension.
- [ROADMAP §6](../ROADMAP.md#6-risks--hard-truths): "Solo/small-team realistic path: M1–M3 is already a serious year" (§6.1); "Clients are the real cost, not the server" (§6.2).
- THREAT_MODEL: [INV-35](../THREAT_MODEL.md#8-security-invariants) (untrusted rich content), INV-55 (signed updates), INV-57 (supply chain), INV-60 (core dumps off, no crash SDK), INV-62 (keystore unlock only behind OS-enforced presence), INV-64 (passkey origin rules), INV-68 (secret input fields), A9, A10, A14, NG-1.
- [CLAUDE.md](../../CLAUDE.md): `unsafe` is forbidden in every crate, with "no workarounds through FFI crates".

### Binding facts (read 2026-09-26)

UniFFI is not yet a workspace dependency (V, `Cargo.toml`). ADR 0013 records 0.32.2 as the version checked in M0, and its §5 requires an exact pin. `rizzy-ffi` does not exist yet (ADR 0016: M7).

| Language | Generator | Maintenance | Latest release, target UniFFI | State |
|---|---|---|---|---|
| Swift, Kotlin | UniFFI, first-party | Mozilla; "full support" for Kotlin, Swift and Python (V) | uniffi 0.32.2, 2026-09-23 (V) | Bitwarden's SDK (its main branch pins uniffi `=0.32.0`, V) feeds its native Swift and Kotlin apps, which pin versioned SDK builds (V; the uniffi version inside those builds: U). Proton Pass's shared library declares uniffi 0.32 (V). Kotlin calls through JNA 5.12.0 or later (V) |
| C# | uniffi-bindgen-cs (NordSecurity), MPL-2.0 | The only maintainer seen acting on PRs (dfetti) merged the 0.31 upgrade after what he called a "shallow review", saying he lacks time for proper reviews (V). How many maintainers there are was not checked (U). Upstream CI runs on Linux only (V). Draft PR #141, open 13 months, adds Windows CI jobs and a callback vtable crash case (V) | v0.11.0+v0.31.0, 2026-06-23, targets uniffi 0.31.0 through a caret requirement. Not on crates.io; installed from git (V) | 0.32 support exists only as PR #176 from an outside contributor, with no maintainer review (V). The generated C# needs AllowUnsafeBlocks, on .NET 8+ (or .NET Framework 4.6.1 with extra packages) (V). Recent fixes were undefined-behaviour-class bugs at the P/Invoke boundary, among them managed exceptions escaping P/Invoke in callback interfaces and callback futures left suspended (V). Open PRs #182, #185 and #186 address known bugs (V). Nubo intends to build its Windows bindings from a fork (L) |
| C++ | uniffi-bindgen-cpp (NordSecurity), MPL-2.0 | Small (39 stars, V). Not listed in UniFFI's README, which points C and C++ users at Diplomat (V) | Tag v0.9.0+v0.29.4, 2026-08-18; no GitHub releases (V) | Three minors behind 0.32. No async; no configuration in library mode; the generated header order is not deterministic (#65) (V). A 0.31 upgrade is a draft PR (#66) from a repository Collaborator, opened 2026-09-25, with no reviews (V). LiveKit builds from a 0.31 fork (L). How it maps errors, objects and callbacks: U |

- **Lag.** Two measures (V; release dates from crates.io and the generators' repositories):
  - Completed catch-ups: C# shipped 0.29.4 support about 1 month after UniFFI 0.29.4, and 0.31.0 support about 5 months after. C++ shipped 0.29 support about 5 months after.
  - Lags still open on 2026-09-26: C++ has never shipped 0.30.0 (released 2025-10-08, about 11.5 months ago) or 0.31.0 (2026-01-14, about 8.5 months); its only 0.31 work is draft #66. C# has not shipped 0.32.0 (2026-06-30, about 3 months); its only 0.32 work is PR #176. Both skipped 0.30.
  - The slowest generator today is C++, at 0.29.4.
- **Load-time checks.** Generated Kotlin and C# compare the contract version and per-function checksums with the library, and throw on a mismatch (V). The checksums are masked to 16 bits, and uniffi-bindgen-cs has an `omit_checksums` switch (V). The same checks in Swift: L. In C++: U.

### What `forbid(unsafe_code)` proves for generated glue

- rustc 1.94.1 drops an `unsafe_code` diagnostic whose primary span lies in an external macro expansion, whatever the lint level, `forbid` included. Every attribute and derive macro expansion counts as external, and so do proc-macro bang macros (V, rustc source).
- So the M0 results "UniFFI 0.32.2 compiles under `forbid`" and the same for wasm-bindgen 0.2.129 (V, ADR 0013 Risks) prove only this: no `unsafe_code`-linted construct in our source keeps its own span through macro expansion. They do not prove the generated scaffolding has no `unsafe`. It almost certainly has some: the exported `extern "C"` scaffolding needs `no_mangle` or `export_name`, which the lint covers (L, inferred from the exported symbols; S1 confirms by expanding).
- `unsafe` that we write inside a proc-macro input can escape the lint too, if the macro re-spans or consumes those tokens (U). cxx-qt's `unsafe extern "C++"` blocks are the case in point (not compiled, U; S5 probes it).
- Almost any proc-macro generator passes the same way. A `forbid` build catches four things only: `unsafe` in our code that keeps its own span; a generator that re-spans its tokens onto our source; an emitted `#[allow(unsafe_code)]` (E0453 under the command-line `forbid`, L); and a change to rustc's external-macro rule. It does not see new or changed `unsafe` inside generated code. §4.1 adds a check that does.
- The M0 check covered only `setup_scaffolding!`, one function and one Object, on the macOS host (V). Records, enums, error enums, custom types, callback interfaces, and the Android, iOS, Windows and Linux targets are unverified (U).
- The generated glue, the `uniffi` runtime and wasm-bindgen's generated code are therefore third-party `unsafe` in audit scope, like any dependency with `unsafe` inside ([ADR 0009](0009-crypto-dependency-policy.md) checklist item 5).
- **This reaches M1.** ADR 0013 Risks says CI checks `rizzy-wasm` "so an upgrade that brings in `unsafe` fails in its own PR", and ADR 0016 §5 says the same of the R1 build check. By the rule above, that is not true for wasm-bindgen either. ADR 0013 owner decision 1 ("If a future generator ever needs `unsafe`, that is a new ADR") was taken on the premise that generated glue has none. Open question 2 puts this to the owner now, separately from the native clients.

### Precedent (read 2026-09-26)

- **One Rust core under per-platform UIs.** 1Password 8 moved from four separately built platform stacks, which drifted apart in features and behaviour, to one Rust core under every app (V). Its desktop routes favicons and similar requests through the core (a 1Password security lead's personal blog, V that he says so).
- **Native mobile over a Rust core through UniFFI.** Bitwarden (Swift and Kotlin apps in separate repositories, fed by versioned Swift and Maven packages) and Proton Pass (V). Whether Proton's vault encryption runs in its Rust library: U.
- **Native desktops.** None of the password managers surveyed ships three separately built native desktop UIs.
  - 1Password stopped its SwiftUI Mac app and chose not to build a native Windows UI. Its desktops are one Electron app (V).
  - Bitwarden and Proton Pass each ship one Electron desktop (V).
  - KeePassXC is one C++ Qt 6 codebase for all three desktops (V). Enpass's Linux build bundles Qt (V), and it is reportedly one Qt app on every desktop (L).
  - Dashlane dropped its desktop apps in 2022, saying five platforms split its focus (V).
  - Mac commentators objected when 1Password dropped its native Mac app (Six Colors, V).
- **Separate client repositories over a core repository.** Bitwarden, Proton, and Signal: an AGPL Rust core (libsignal) in its own repository, published as artifacts for separate AGPL client repositories (V).
- **Where Bitwarden needed `unsafe`.** Its UniFFI crate has hand-written `unsafe` JNI code, because its Rust SDK does its own HTTPS on Android and must reach the platform certificate verifier (V). Its only C# and C++ route (the Secrets Manager SDK) is a hand-written C ABI with `unsafe` (V).

### Security trade-off

- **Gained.** Native UIs remove the threat ADR 0015 called the main desktop threat: XSS in the webview calling IPC to pull every item.
- **Lost: the process boundary Tauri gave.** The whole native UI now runs in the process that holds the keys. (Mobile had this exposure under ADR 0013 already.)
  - **The host language.** C#, Swift and Kotlin are memory-safe languages next to Rust. A C++ Qt host is memory-unsafe code in the path of the master password and of revealed values (ADR 0013 §3 rule 2). ADR 0013 rejected a C/C++ core for that reason. (Memory-safety characterisation of the languages: general knowledge, L.)
  - **The UI frameworks, on every platform.** Text layout, rich-text parsers and image codecs are C, C++ or Objective-C code: WinUI/XAML, AppKit and ImageIO, Skia on Android, Qt Quick (general knowledge, L). Under Tauri they parsed untrusted input in the webview's separate renderer process. Now favicons, item text, imports and shared content reach them next to the keys. §5.1 limits what they see.
  - **TB-10** becomes an audit boundary on every native client, as it already is in the browser. "Keys stay in Rust" is an API rule (ADR 0013 §3), not a memory boundary.
- **Unchanged limit.** Managed strings (.NET, Swift, Kotlin) and `QString` cannot be reliably wiped, like JavaScript strings in [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene) (general knowledge, U).
- **New limit.** The buffers that the generated glue and the binding runtime use to pass values across the boundary are not wiped either, on the Rust side or in the host. A `Zeroizing` type cannot cross the boundary; only the copy that stays in Rust is wiped. For UniFFI, `RustBuffer` is freed by rebuilding and dropping a plain `Vec` (the review's reading of `uniffi_core`'s `rustbuffer.rs`, not in the research sheet: L). This affects every named exception and every revealed value. §3 reduces it; CRYPTO.md §12.2 lists it (On acceptance).

## Decision

Text under an **Owner decision** label restates the owner's decisions of 2026-09-26 ([full text](#owner-decisions-2026-09-26)). Text labelled "proposed" is the draft the owner accepted on 2026-09-27, with the answers in [Owner decisions (2026-09-27)](#owner-decisions-2026-09-27).

### 1. What this ADR supersedes

**Owner decision 6:** changes to parts of an Accepted ADR take effect by partial supersession, through ADR 0020, a small successor to ADR 0001. A new ADR may supersede named sections of an Accepted ADR. The older ADR's status becomes "Partially superseded by ADR NNNN (§x, §y)". Everything not named stays binding. The owner chose this over restating ADRs 0013 and 0016 in full.

**Proposed:**
- **ADR 0015 is superseded in full** (§1.1). Its status becomes "Superseded by ADR 0019" (ADR 0001 point 3). The parts this ADR keeps are restated in the Decision sections that §1.1's third column names, and bind through those sections.
- **ADR 0013, ADR 0016 and ADR 0009 are partially superseded** (§1.2–§1.4), under ADR 0020 point 9. Only the parts named there stop binding. Everything else in them stays binding, their owner decisions included, and is not restated here.
- **The tables bind.** In the Part tables of §1.2 and §1.3, the ADR 0009 table included, the first column names one part. Those tables are exhaustive, and they are the list that binds. The other subsections work differently:
  - §1.1 names ADR 0015 whole, because it is superseded in full. Its third column points to the Decision sections that restate what this ADR keeps. Those sections bind; the column does not.
  - §1.4 is replacing text, which rows of §1.2 and §1.3 point to.
  - §1.5 gives the share and the reference search.

  The status lines below are signposts. In the Replaced by column and in §1.4, a section reference with no ADR named is to this ADR.
- **Locator granularity.** Every row names a part of a kind ADR 0020 point 9 allows (a section, a rule, a table row, a whole bullet or sentence), or the Milestone line. ADR 0013's §1 "Native hosts" Crate cell and §2 "Desktop (Tauri)" column were re-cut to whole rows on 2026-09-27 and restated in full (§1.2, §1.4).
- **Status lines,** set by the owner (ADR 0020 point 9). Each line gains this entry after any earlier one, separated by a semicolon:
  - ADR 0013: "[ADR 0019](0019-native-clients.md) (Milestone line, Context in part, §1 in part, §2 in part, §3 in part, §5, §6 in part, Negative in part, Risks in part)".
  - ADR 0016: "[ADR 0019](0019-native-clients.md) (§3 in part, R2 in part, R5, R6, R7 in part, §5 in part, §7, Risks in part, Alternatives considered in part)".
  - ADR 0009: "[ADR 0019](0019-native-clients.md) ("RNG rules" in part)".
- **Generated `unsafe`.** Three parts rest on the premise that generated glue has no `unsafe` (Context): ADR 0013 Risks, first bullet's closing paragraph; ADR 0016 R7, second sentence; ADR 0016 §5, R1 build-side row, last sentence. They stay in §1.2 and §1.3; no separate ADR takes them (owner decision 7).
- **Share and references.** §1.5 gives each older ADR's share, with ADR 0022's parts, and the dated reference search, with a reading for each reference. Every share is below half. No reference needs a further row. The ADR 0009 row (§1.3) comes from a rule that lists crate kinds, not from a citation.

These tables list every change found in a line-by-line read of ADRs 0013, 0015 and 0016 on 2026-09-26, re-checked against the review of the same day, and against ADRs 0020 and 0022 as accepted on 2026-09-27.

#### 1.1 ADR 0015 (superseded in full)

| Accepted text | Replaced by | Carried forward into this ADR |
|---|---|---|
| ADR 0015, all | This ADR. Point 4's INV-35 rule ("Frames are used only for sandboxed untrusted content") by §5.1. Point 9's Windows Hello clause by §2.1 (Windows biometric unlock out of scope until CRYPTO.md or an ADR specifies it; open question 8) | Each item names the section that restates it and binds. Owner decision 1: macOS notarization from the first release, Windows signing before M8 (§2 table, column "Packaging and signing", rows macOS and Windows). Owner decision 2: AppImage and `.deb` first, Flatpak later (§2 table, row Linux). Owner decision 4: 30 s default clipboard clear, configurable (§5, row Clipboard). Point 3: external links open in the system browser, only for `http` and `https` (§5.1; INV-42). Point 7, first half: release builds carry no debugger or inspector surface, per platform (§6, "Release hardening per platform"). Point 7, second half: no custom URI scheme or deep link without an ADR, and its input is untrusted (§6, "IPC surfaces"). Point 8's updater rules, key loss included: restated per channel in §12. Point 9, except its Windows Hello clause: restated word for word in §5.2. Point 10: desktop↔extension integration needs its own ADR (§6, "IPC surfaces"). Owner decision 3 (Tauri crate in the workspace) lapses |

#### 1.2 ADR 0013 (partially superseded)

| Part (row label) | Replaced by | Carried forward unchanged: stays binding in ADR 0013 |
|---|---|---|
| Milestone line | The line, restated: "M1 (wasm for the web vault, native for the CLI) / M3 (native desktop bindings) / M7 (UniFFI)" | – (the whole line is restated) |
| Context, "In Tauri and on mobile it is a process or language boundary, and keys can stay on the Rust side." (its last sentence) | "On every native client, mobile included, the Rust core runs in the host's process. There, as in the browser, the boundary is an audit boundary (TB-10), not a memory boundary. Keys stay on the Rust side as an API rule (ADR 0013 §3 rule 1)." ([Security trade-off](#security-trade-off)) | The browser sentences before it, and the rest of Context |
| §1 row "Native hosts" | The row, restated: Layer "Native hosts"; Crate "`rizzy-cli` (M1)"; Contents "link `rizzy-client` directly, with no FFI"; Runs on "Linux, macOS, Windows". `rizzy-desktop` is dropped because there is no Rust desktop host. Native desktop clients reach `rizzy-client` through the binding crates (next row; §3; §4) | – (the whole row is restated). Every other row, except the next |
| §1 row "Bindings" | The row, restated. `rizzy-wasm` (M1): thin generated wrapper over `rizzy-client`; runs on wasm32 (ADR 0013's text for it, in the singular). `rizzy-ffi` (M3): UniFFI bindings over `rizzy-client`; runs on Android, iOS, macOS and Windows. `rizzy-ffi-cpp` (with the Linux client): Diplomat bindings over `rizzy-client`; runs on Linux. Both follow the routes of §4. For the platforms it serves, each also holds the sqlx cache and the INV-60 init check, and on Windows (`rizzy-ffi`) and Linux (`rizzy-ffi-cpp`) the HTTP client, through which it drives `rizzy-client`'s state machine (§5; owner decision 11). They are more than thin wrappers | – (the whole row is restated) |
| §1, the sentence after the table: "No TypeScript, Kotlin or Swift code implements cryptography, envelope parsing, signature checks, merge or URL matching." | §3, "The rule, in this ADR's words", which adds C# and C++, signed-statement handling, OPAQUE and sync | – (the principle is restated in §3) |
| §2 table, header row "Capability" | §1.4, ADR 0013 §2 table, its header row: the "Desktop (Tauri)" column is dropped from every row. Native desktops: §5 and §5.2 | The rest of §2: the sans-I/O client, the rustls rule for Rust HTTP |
| §2 table, row "HTTP transport" | §1.4, the same row | – (the whole row is restated) |
| §2 table, row "Persistent storage (opaque bytes)" | §1.4, the same row | – (the whole row is restated) |
| §2 table, row "Randomness" | §1.4, the same row | – (the whole row is restated) |
| §2 table, row "Wall clock" | §1.4, the same row | – (the whole row is restated) |
| §2 table, row "Key storage for local unlock" | §1.4, the same row | – (the whole row is restated) |
| §3 first sentence: "These rules apply to `rizzy-wasm`, `rizzy-ffi` and the Tauri IPC commands (ADR 0015)." | "These rules apply to every binding crate (`rizzy-wasm`, `rizzy-ffi` and `rizzy-ffi-cpp`) and to every host that calls one." (§3) | Rules 1–6 and 8, word for word, with the named-exception list (its pairing QR sub-bullet superseded by [ADR 0022](0022-server-mode-only.md)) |
| §3 rule 7 | Rule 7, restated: "**Bindings are generated.** wasm-bindgen, first-party UniFFI (Swift, Kotlin), uniffi-bindgen-cs (C#; owner decision 8) and Diplomat (C++; owner decision 9) generate the glue, each pinned as §4.1 says. Any other generator, a fork, or a PR pinned at a commit needs a new ADR. There is no hand-written C ABI and no hand-written `unsafe`, in any Rust crate. Host code follows §4.5 (owner decision 10)." | – (the whole rule is restated; its ban on a hand-written C ABI and hand-written `unsafe` is kept and applied to every Rust crate; host code follows §4.5) |
| §5 | §4.1 and §4.2, for every native platform. §4.2 restates §5's three bullets: the exact UniFFI pin, with upgrades handled like crypto crates; the Kotlin and Swift packages generated from `rizzy-ffi` in CI; the iOS AutoFill sentences, word for word | – (the whole section is named) |
| §6 first bullet, third item: "from M7, through Kotlin and Swift." | §10 | The native and wasm runs; byte-equal outputs as a release blocker; the flow tests against the simulated server |
| Negative, first bullet: "Every client build needs Rust, plus wasm or UniFFI tooling in CI." | "Every core release, and every build from source (§7), needs Rust plus wasm and the binding-generator tooling of §4. Client repositories hold no Rust (§6) and consume released artifacts (§7)." | The second, fourth and fifth bullets |
| Negative, third bullet: "Two binding generators, both pre-1.0 (wasm-bindgen 0.2.x, UniFFI 0.32). Either can break on upgrade." | "Four binding generators, all pre-1.0: wasm-bindgen, UniFFI, uniffi-bindgen-cs and Diplomat (§4). Any of them can break on upgrade." | The second, fourth and fifth bullets |
| Risks "Generated code and the unsafe ban.", its closing paragraph: "A generator upgrade could change this. `rizzy-wasm` is checked for wasm32 and `rizzy-ffi` for the host in CI ([ADR 0016](0016-workspace-layout.md) §5), so an upgrade that brings in `unsafe` fails in its own PR. See open question 1." | "Generated glue compiles under `forbid` because rustc does not report the lint inside external macro expansions, and it contains `unsafe` (L; Context). The M0 results show what compiles, not that the glue has no `unsafe`. §4.1's baseline review, not the `forbid` build, catches changes to generated `unsafe` (owner decision 7)." | The bullet's label and its two M0 results, as facts about what compiles. Owner decision 1 stays binding: no `unsafe` exception for our crates, `forbid` in every crate, and the exception mechanism. Only its premise, stated in this paragraph, is corrected |
| Risks, fourth bullet: "UniFFI could stall before 1.0. The fallback is a thin C ABI over `rizzy-client` from a different generator. That may need `unsafe`, which the current rules do not allow (open question 1)." | "UniFFI or a third-party generator could stall before 1.0. There is no hand-written C ABI fallback without a new owner decision (§3). A generator that rule 7, as restated above, does not admit needs a new ADR." | The other bullets |

#### 1.3 ADR 0016 (partially superseded)

| Part (row label) | Replaced by | Carried forward unchanged: stays binding in ADR 0016 |
|---|---|---|
| §3 row "`rizzy-desktop`" | Withdrawn: there is no Rust desktop host and no Tauri shell (§1.1). Native desktop clients use the binding crates of §1.4 | Every other row, except the next and `rizzy-domain-relay` (superseded by ADR 0022), and the notes |
| §3 row "`rizzy-ffi`" | §1.4, rows `rizzy-ffi` and `rizzy-ffi-cpp` | – (the whole row is restated) |
| R2 item (c) | §1.4, R2 item (c) | R2 items (a) and (b); every rule not named here |
| R5 | §1.4, R5 | – (the whole rule is restated) |
| R6 | §1.4, R6 | – (the whole rule is restated) |
| R7 second sentence: "There is no exception, and the binding crates do not need one: generated wasm-bindgen and UniFFI glue compiles under `forbid` (ADR 0013, Risks)." | "There is no exception for our own code. Generated binding glue compiles under `forbid` only because rustc does not report the lint inside external macro expansions, and it contains `unsafe` (Context). §4.1's baseline review is the check that sees changes to it (owner decision 7)." | R7's first sentence (`workspace = true`, `unsafe_code = "forbid"`), and the exception mechanism, should one ever be needed |
| §5 row "R1, build side", its last sentence: "A binding-generator upgrade that brings in `unsafe` or breaks the wasm build then fails in its own PR." | "A binding-generator upgrade that breaks the wasm build then fails in its own PR. Changes to generated `unsafe` are caught by §4.1's baseline review, not by this check." | The rest of the row, and the rest of §5 except the next row |
| §5 "cargo-deny, second layer", its first bullet: "`sqlx` with wrappers = `rizzy-storage`, the domain crates and the native client leaf crates (`rizzy-cli`, `rizzy-desktop`, `rizzy-ffi`, R5);" | §1.4, the `sqlx` entry | The other entries, and the paragraph after them |
| §7 | §1.4, §7: the layout restated without desktop, android and ios under `apps/` and without the M3 `members` sentence. Desktop and mobile apps live in their own repositories (§6), and no directory under `apps/` joins the Cargo workspace | – (the whole section is restated, "`fuzz/` stays excluded." included) |
| Risks, third bullet: "The Tauri crate brings GUI system dependencies into workspace CI (ADR 0015, open question 3)." | "Core CI, which already tests on Linux, macOS and Windows, gains cross-compilation targets and the further runners and jobs that the §10 vector suite and smoke tests need (§7), not GUI toolkits." | The other bullets |
| Alternatives considered "Separate repositories per component." | §6: separate client repositories, with all Rust in this repository. The cost ADR 0016 names, a protocol change across repositories, is in this ADR's Negative consequences ("Governance") | The other alternatives |

**ADR 0009.** Its "RNG rules", third bullet, reads "Only leaf crates (CLI, server, Tauri shell, UniFFI bindings, wasm bindings) depend on `getrandom` directly." The parenthesis names crate kinds. `rizzy-ffi-cpp`, a `#[diplomat::bridge]` crate (owner decision 9), is none of them, so the row below applies. Superseding part of a crypto-policy ADR is the owner's call; the owner made it by accepting the answer to open question 4, which named this row as a cost.

| Part | Replaced by | Carried forward unchanged: stays binding in ADR 0009 |
|---|---|---|
| "RNG rules", third bullet: "Only leaf crates (CLI, server, Tauri shell, UniFFI bindings, wasm bindings) depend on `getrandom` directly. They pass `rand_core::UnwrapErr(getrandom::SysRng)`. Only the wasm bindings crate enables `wasm_js`." | "Only leaf crates (CLI, server, wasm bindings and the native binding crates of ADR 0019 §4) depend on `getrandom` directly. They pass `rand_core::UnwrapErr(getrandom::SysRng)`. Only the wasm bindings crate enables `wasm_js`." | The other bullets of "RNG rules", and every other part of ADR 0009 |

ADR 0009 owner decision 1 lists `rizzy-desktop` among the crates that openssl must never reach. That rule first says openssl is reachable "only from `rizzy-server` and the domain crate that does WebAuthn", so it already covers every binding crate, and the name `rizzy-desktop` imposes nothing. Owner decision 1 is not superseded. The xtask lists replace `rizzy-desktop` with the new binding crates (On acceptance).

#### 1.4 Replacing text for ADR 0013 §2 and ADR 0016 §3, §4, §5 and §7

Written as the older ADRs' rows and layout block are. Section references inside these rows and the block, with no ADR named, are to this ADR.

**ADR 0013 §2, capability table** (native desktop clients: §5 and §5.2):

| Capability | Web vault | Extension (M2) | Mobile | CLI |
|---|---|---|---|---|
| HTTP transport | `fetch` | `fetch` | platform HTTP stack | Rust HTTP client, rustls |
| Persistent storage (opaque bytes) | **none**: everything stays in memory. Only the Secret Key goes into browser storage, and only if the user opts in ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)). The web vault is not a durable device | IndexedDB, for wrapped device state and ciphertext only ([INV-63](../THREAT_MODEL.md#8-security-invariants)) | SQLite | SQLite |
| Randomness | getrandom 0.4 with `wasm_js`, in `rizzy-wasm` only | same as web vault | getrandom | getrandom |
| Wall clock | `Date.now()` through the binding | same as web vault | std | std |
| Key storage for local unlock | none | none. Unlocked keys stay in memory in the long-lived context (ADR 0013 §4), or in `storage.session` (ADR 0013 §3 rule 2, INV-63) | Keychain / Keystore, under INV-62 (M7) | OS keyring, or a 0600 file, for device state only. Never a keystore-unlock secret, because neither enforces user presence (INV-62) |

**ADR 0016 §3, planned crates:**

| Crate | Kind | From | Purpose | May depend on (internal) | wasm32, no I/O |
|---|---|---|---|---|---|
| `rizzy-ffi` | lib | M3 | UniFFI bindings over `rizzy-client`: Swift and Kotlin (first-party) for macOS, iOS and Android, C# (uniffi-bindgen-cs) for Windows (§4). For the platforms it serves, it also holds the sqlx cache and the INV-60 init, and on Windows the HTTP client, through which it drives `rizzy-client`'s state machine (§5) | client | no; a leaf |
| `rizzy-ffi-cpp` | lib | the Linux client's milestone (owner decision 12) | Diplomat (`#[diplomat::bridge]`) bindings over `rizzy-client` for Linux: the same coarse API as `rizzy-ffi` (§3), in Diplomat's form (§4.4). It also holds the sqlx cache, the INV-60 init and the HTTP client, through which it drives `rizzy-client`'s state machine (§5) | client | no; a leaf |

**ADR 0016 §4, dependency rules:**

| Rule | Statement |
|---|---|
| **R2** item (c) | (c) Only the leaf crates depend on getrandom directly: `rizzy-server`, `rizzy-cli`, `rizzy-wasm`, `rizzy-ffi` and `rizzy-ffi-cpp` (plus `xtask`). Only `rizzy-wasm` enables `wasm_js`. |
| **R5** Who holds what | Only `rizzy-storage`, the `rizzy-domain-*` crates and the native client leaf crates (`rizzy-cli` from M1, `rizzy-ffi` from M3, `rizzy-ffi-cpp` with the Linux client) depend on sqlx. The client leaf crates enable only its `sqlite` driver. Only `rizzy-server` depends on the domain crates, `rizzy-smtp-ingress` and `rizzy-icon-proxy`. |
| **R6** Client and server are separate | Client-side crates (`rizzy-client`, `rizzy-import`, `rizzy-match`, `rizzy-wasm`, `rizzy-ffi`, `rizzy-ffi-cpp`, `rizzy-cli`) never depend on server-side crates (`rizzy-storage`, `rizzy-bus`, `rizzy-domain-*`, `rizzy-smtp-ingress`, `rizzy-icon-proxy`, `rizzy-server`), and the reverse holds too. The shared crates are `rizzy-core`, `rizzy-sync` and `rizzy-proto`. |

**ADR 0016 §5, cargo-deny second layer, first bullet:**
- `sqlx` with wrappers = `rizzy-storage`, the domain crates and the native client leaf crates (`rizzy-cli`, `rizzy-ffi`, `rizzy-ffi-cpp`; R5 above);

**ADR 0016 §7, repository layout:**

```
crates/     Rust workspace members: libraries, rizzy-server, rizzy-cli, xtask
apps/       user-facing apps (ADR 0014): web, extension, share (M5)
packages/   shared TypeScript packages: core, ui, i18n, config
docs/       ROADMAP, THREAT_MODEL, CRYPTO, adr/
deploy/     Containerfile, compose.yaml per profile, Quadlet units (M1/M3; ADR 0010)
fuzz/       cargo-fuzz targets. Its own workspace on the nightly toolchain, outside the
            main workspace (ADR 0009, open question 4)
```

Desktop and mobile apps live in their own repositories (§6). No directory under `apps/` joins the Cargo workspace. `fuzz/` stays excluded.

#### 1.5 Share and references

**Share.** Words of each older ADR's Decision that the parts in force replace, against the Decision's total (ADR 0020 point 9). Counted with `wc -w` from `## Decision` up to `## Consequences` (headings, owner decisions, table pipes and code blocks included), 2026-09-27 (V for the counts as run). A named row, bullet or section counts its whole lines; a named sentence or item counts its own words. The three Decisions are unchanged since acceptance; ADR 0009 has gained only an `## Amendments` entry, which does not touch "RNG rules". ADR 0022's parts are counted with this ADR's; no other partial supersession of these ADRs is in force. Parts outside the Decision (Milestone line, Context, Negative, Risks, Alternatives considered) do not count.

| Older ADR | Parts named here, in words | ADR 0022's parts | Both, share |
|---|---|---|---|
| ADR 0013 (1,740 words) | §1 rows "Native hosts" 20 and "Bindings" 19; §1 sentence after the table 16; §2 table, six rows 196; §3 first sentence 13; §3 rule 7 20; §5 60; §6 first bullet, third item 7. Total 351 | §3 rule 2, pairing QR sub-bullet 30 | 381, about 22 % |
| ADR 0016 (2,542 words) | §3 rows "`rizzy-desktop`" 20 and "`rizzy-ffi`" 18; R2 item (c) 21; R5 49; R6 42; R7 second sentence 23; §5 R1 build-side row, last sentence 18; §5 cargo-deny `sqlx` entry 19; §7 89. Total 299 | §3 row `rizzy-domain-relay` 22 | 321, about 13 % |
| ADR 0009 (1,831 words) | "RNG rules", third bullet 26 | – | 26, about 1.4 % |

Each share is below half.

**References.** `git grep -n --untracked` over the working tree on 2026-09-26 for "ADR 0013", "ADR 0016", their file names, `rizzy-desktop`, `src-tauri`, `apps/desktop`, `apps/android`, `apps/ios` and "RNG rules". Each ADR's citations of itself, and this ADR, are left out. About 30 lines cite ADR 0013 and about 290 cite ADR 0016. Each hit that invokes, quotes or restates a named part is listed with its reading. The readings are: it reads through to the replacing text; it describes the text as accepted; it is edited under On acceptance; or it needs a further row. No hit needs a further row.

| References | Part | Reading |
|---|---|---|
| README index row 0013, Milestone cell "M1 (wasm, CLI) / M3 (Tauri) / M7 (UniFFI)" | ADR 0013 Milestone line | Edited under On acceptance |
| THREAT_MODEL Q-13, "(ADR 0013 §5)" | ADR 0013 §5 | Reads through to §4.2, which restates the iOS AutoFill sentences word for word |
| ADR 0014: Context, "ADR 0013 §5 and ADR 0016 §7 (Accepted) bind mobile today" and, under "Not in this ADR", "Mobile: ADR 0013 §5 and ADR 0016 §7 (M7). Both move to ADR 0019 if it is accepted"; §4, "ADR 0016 §7 governs `apps/` and lists `apps/desktop`, `apps/android` and `apps/ios`" | ADR 0013 §5; ADR 0016 §7 | Describe the text as accepted, and say it moves to this ADR on acceptance |
| THREAT_MODEL §8.10 row "ADR 0013 §2 table, ADR 0015 §9"; AST-22 "ADR 0013 §3, ADR 0015 §9" | ADR 0013 §2 in part (the table rows), §3 in part | Read through: §1.4 restates the table without its Desktop column, whose keystore cell goes to §5 and §5.2, which keep INV-62; this ADR does not name §3 rule 2. The ADR 0015 §9 halves are edited under On acceptance |
| THREAT_MODEL §3.3 TB-10, "In Tauri and mobile it is a process or IPC boundary" | ADR 0013 Context, last sentence (the same claim; not a citation) | Edited under On acceptance |
| THREAT_MODEL §3.1 Desktop app row, "Tauri: Rust backend linked to `rizzy-core`" | The Rust desktop host (ADR 0013 §1, ADR 0016 §3 `rizzy-desktop`), through ADR 0015 | Edited under On acceptance |
| CRYPTO.md §1 goal 6, "native, wasm32 and UniFFI (ADR 0013)" | ADR 0013 §1, sentence after the table (the same principle) | A whole-ADR citation, so it reads through; its wording is edited under On acceptance |
| ADR 0013 §2, "ADR 0009's RNG rules as ADR 0016 R2 states them"; ADR 0009 "RNG rules", "ADR 0016 R2"; CLAUDE.md, "ADR 0016 R1–R2"; xtask `check.rs` and its tests, "ADR 0016 R2" and "R1/R2" | ADR 0016 R2 in part | Read through: the restated item (c) keeps "only leaf crates depend on getrandom directly" and "only `rizzy-wasm` enables `wasm_js`". CLAUDE.md's crate-boundary summary is also edited under On acceptance |
| ADR 0011, "ADR 0016 R5 allows exactly those client leaf crates to depend on sqlx"; xtask `rules.rs` (the `Side` and `Sqlx` docs) and `check.rs` and its tests, "ADR 0016 R5" and "R6" | ADR 0016 R5, R6 | Read through to §1.4's R5 and R6. The xtask rules table and tests are edited under On acceptance |
| xtask `check.rs` and its tests, "ADR 0016 §3"; `rules.rs`, "ADR 0016 §2/§3" and "§3–§5" | ADR 0016 §3 in part | Read through: the unnamed rows stay, and the two named rows go to §1.4. The rules table and the test that restates §3 (`rows_match_adr_0016`) are edited under On acceptance |
| `rizzy-desktop`: xtask `rules.rs` (its rule row, and the tests at lines 609, 621, 660 and 682); ROADMAP §4.1 workspace row; ADR 0009 owner decision 1 ("never from … or `rizzy-desktop`") | ADR 0013 §1 row "Native hosts"; ADR 0016 §3 row "`rizzy-desktop`" (Withdrawn) and the name in R2 item (c), R5, R6 and the `sqlx` entry | The name imposes nothing. xtask and ROADMAP are edited under On acceptance. ADR 0009 is Accepted and not edited (ADR 0001 point 4); its "only from `rizzy-server` and the domain crate that does WebAuthn" covers every binding crate (§1.3) |
| ADR 0015 point 2, "The Rust side (`rizzy-desktop`, in `apps/desktop/src-tauri`) links `rizzy-client` directly (ADR 0013)" | ADR 0013 §1 | Describes the text as accepted; ADR 0015 is superseded in full (§1.1) |
| Code comments "ADR 0016 R7" (`rizzy-cli`, `rizzy-core`, `rizzy-server`, `rizzy-sync`, xtask); CONTRIBUTING, "ADR 0016 R7 rules out per-crate `[lints]` tables"; xtask "R7" and "R7/R8" messages; ADR 0013 owner decision 1, "`xtask`'s R7 check" | ADR 0016 R7 in part | Read through: R7's first sentence and the exception mechanism are not named and stay binding |
| `.cargo/config.toml`, `.github/workflows/ci.yml`, CONTRIBUTING, both `clippy.toml` files, `Cargo.toml`, xtask (`main.rs`, `check.rs`, `rules.rs`, `Cargo.toml`), ADR 0010: "ADR 0016 §5" | ADR 0016 §5 in part | Read through: they cite the checks (xtask, the clippy lists, `check-wasm`, the image build), which are not named. The R1 build-side row keeps its check |
| ADR 0016 R7, "(ADR 0013, Risks)"; ADR 0013 Risks, "(ADR 0016 §5), so an upgrade that brings in `unsafe` fails in its own PR" | ADR 0013 Risks; ADR 0016 §5 R1 build-side row | Each sits inside a part this ADR names (R7 second sentence; the Risks closing paragraph), so it needs no reading |
| `fuzz/Cargo.toml`, `Cargo.toml`, `.github/dependabot.yml`, `ci.yml` and CONTRIBUTING, "ADR 0016 §7" (`fuzz/` is its own workspace); xtask `check.rs`, "lives where ADR 0016 §1 and §7 say" | ADR 0016 §7 | Read through to §1.4's §7, which keeps `fuzz/` as its own workspace outside the main one. xtask's `rizzy-desktop` directory rule is edited under On acceptance |
| xtask `check.rs` and `rules.rs`, "(ADR 0016, Risks)" | ADR 0016 Risks in part (first bullet) | Read through: the first bullet is not named |
| CRYPTO.md §12.1, "Tauri shell, UniFFI bindings" (not a citation); `rizzy-core` `rng.rs`, xtask and CLAUDE.md, "ADR 0009 RNG rules" | ADR 0009 "RNG rules", third bullet | CRYPTO.md is edited under On acceptance. The others cite the rules as a whole or the `rand` 0.8 bullet, and read through |
| ADR 0020, where it cites parts of ADR 0013 and ADR 0016 as examples | several | Describe the text as accepted |
| Whole-ADR citations and citations of parts not named: References lists and "Related" lines; ADR 0002 "(ADR 0016 §3)" on the `openapi` feature; ADR 0003 Context; ADR 0011 on the storage interface; ADR 0012; ADR 0017; CRYPTO.md §4.2; THREAT_MODEL's web-vault row and its extension and CLI key-custody text (ADR 0013 §2, other columns); ADR 0014 on ADR 0013 §4 and owner decision 1; ADR 0022 on ADR 0013 §3 rule 2 and ADR 0016 §3's `rizzy-domain-relay` row | whole ADR, or parts not named | Read through; not listed one by one |

### 2. Platforms and toolkits

**Owner decisions 2 and 3:** Windows = WinUI 3 with C#/.NET; Linux = Qt 6 with Qt Quick/QML, chosen over GTK for control over the look; macOS and iOS = SwiftUI; Android = Kotlin. Repositories: `rizzy-vault-apple` (macOS, iOS, the AutoFill credential providers, the Safari wrapper if one is built), `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`.

**Proposed.** In the table, the toolkit and language that open each "Toolkit, language" cell, and the Repository column, restate those decisions. Everything else is proposed: versions, styles, module rules, minimum OS, packaging, integrations, and what is out of scope.

| Platform | Toolkit, language | Minimum OS | Packaging and signing | Platform integrations | Repository |
|---|---|---|---|---|---|
| Windows | WinUI 3 on Windows App SDK 2.x (2.5.1, 2026-09-16; 2.x serviced to 2027-04-29) (V). C# on .NET: uniffi-bindgen-cs needs .NET 8 or later (V). The target runtime is a supported LTS chosen in M3; .NET 8's support is reported to end in November 2026 (U) | Windows 10 1809 (build 17763) is the SDK's compatibility floor. Microsoft supports it only on Windows releases still in support (V). x64 and Arm64 | Windows builds are signed before M8 (ADR 0015 owner decision 1). Before signing: unpackaged and self-contained, which is allowed, though not as a single-file EXE (V), with SmartScreen warnings. Then Authenticode-signed MSIX, or the Microsoft Store, which signs submissions (V), if ADR 0017 allows it (§15 item 3). Azure Artifact Signing is open only to organisations in the USA, Canada, the EU and the UK with three years of tax history, and to individuals in the USA and Canada (V); otherwise an OV certificate | Windows Hello unlock: out of scope (§2.1, open question 8). Global hotkey; clipboard with the concealed hint (AR-16). Accessibility through UI Automation; custom controls need an AutomationPeer (V) | `rizzy-vault-windows` |
| Linux | Qt 6 Quick/QML with a custom style based on Basic (our pick; Qt advises basing custom controls on one of Basic, Fusion, Imagine, Material or Universal, and says the macOS and Windows styles are unsuitable, V). LGPLv3 modules only, linked dynamically, subject to ADR 0017 granting the Qt exception (§15 item 5). None of the 14 GPL-only modules, which include Qml Compiler, Quick Timeline and Virtual Keyboard (V). Host language C++; binding route: Diplomat, subject to S3 (§4.4; owner decision 9) | Set with the Qt version in M3 (U). Qt: follow the open-source minors, because open-source LTS patches after the first year are commercial-only (V). 6.12 had its RC on 2026-09-18; final planned for 2026-09-30 (V) | AppImage and `.deb` first; Flatpak on the KDE runtime later, which keeps Qt replaceable (V). A bundled Qt in an AppImage probably needs Qt's source in the release archive under LGPLv3 §4(d)(0) (L: our reading of the licence) | No keystore unlock: no Linux secret store enforces user presence (Secret portal and QtKeychain backends, V), so INV-62 applies unchanged. Global hotkey through the GlobalShortcuts portal on Wayland (V; which desktops implement it, U). QML loads only from compiled-in resources (`qrc`), never from disk or the network | `rizzy-vault-linux` |
| macOS | SwiftUI, Swift; one Xcode multiplatform target shared with iOS (V) | macOS 14 if the AutoFill provider handles passkeys, which needs it (V); otherwise set in M3 (U). A macOS provider is a Should in M7 (owner decision 12) | Developer ID and notarization from the first release. Mac App Store only if ADR 0017 allows it (§15 item 3) | AutoFill credential provider (`ASCredentialProviderViewController`, macOS 11+, V), in M7 (owner decision 12). Keychain with a biometry access-control flag under INV-62 (exact APIs confirmed in M3, U). The Safari wrapper, if built (§2.2) | `rizzy-vault-apple` |
| iOS | SwiftUI, Swift; shared target with macOS | iOS 17, for passkey requests (V) | App Store, subject to ADR 0017 (§15 item 3) | AutoFill credential provider. Its memory cap of about 120 MB comes from secondary sources only (L); `rizzy-ffi`'s footprint is measured in M7. Keychain and Secure Enclave with biometry (INV-62) | `rizzy-vault-apple` |
| Android | Kotlin; Jetpack Compose recommended (ui 1.12.1, material3 1.4.0, V) | API 26, for the Autofill Framework (V). The passkey provider (`CredentialProviderService`) needs API 34 (V); androidx.credentials 1.6.0 stable, not the guide's alpha (V) | Google Play, subject to ADR 0017 (§15 item 9). Native libraries 16 KB-page aligned: Play requires it for apps targeting API 35+, and blocks updates without it from 2027-02-01 (V). Whether JNA's `libjnidispatch.so` is aligned: U. F-Droid only through the build-from-source path (§7) | `AutofillService` with inline suggestions (V); no accessibility fallback (INV-41). Keystore with StrongBox or TEE plus BiometricPrompt (INV-62). JNA on its Apache-2.0 option (V) | `rizzy-vault-android` |

Milestones per platform: owner decision 12.

#### 2.1 Windows biometric unlock (owner decision 13)

- Out of scope until CRYPTO.md, or an ADR, specifies the construction. CLAUDE.md forbids home-made constructions.
- Why:
  - Windows Hello key credentials are documented as RSA-2048 signing keys (V).
  - A newer `RequestDeriveSharedSecretAsync` exists on SDK 26100 and later, but its inputs and outputs are undocumented (V that it exists, U what it computes). Hashing a signature instead needs deterministic signatures (U).
  - A Microsoft Q&A answer says credentials created by unpackaged or full-trust apps are scoped to the user, not the app: any same-user process can use them after a Hello prompt. Only an AppContainer MSIX gets per-app isolation (L). That conflicts with the unsigned, unpackaged route before M8.
- Effect: Windows unlocks with the master password only until that design exists. This narrows ROADMAP §4.3's biometric Should (M3) for Windows. It is met on macOS, iOS and Android. The owner deferred it (owner decision 13); the ROADMAP note is in On acceptance.

#### 2.2 Safari (owner decision 15)

- ROADMAP §4.4 lists a Safari extension as a Should in M3. If one is built, its web code is `apps/extension` from this repository, taken as a release artifact (§7), and its Xcode wrapper lives in `rizzy-vault-apple` (owner decision 3). Safari 15.4 and later support MV3, and `xcrun safari-web-extension-packager` wraps an existing extension (V).
- It needs its own key-custody ADR first. ADR 0013 §4 keeps the wasm core in one long-lived context.
  - iOS Safari has none: every background page is non-persistent there (V).
  - On macOS a persistent MV2 background page is probably allowed (L).
  - Whether Safari's extension CSP allows wasm compilation (`wasm-unsafe-eval`) is U. If it does not, `apps/extension` cannot host the core in Safari, and native custody becomes the only option.
  - Custody in native code, reached through `sendNativeMessage` to the app extension (V), is a new IPC surface, like desktop↔extension integration, which needs its own ADR (§6, "IPC surfaces").
- On macOS the containing app can ship with Developer ID and notarization (V). On iOS it goes through the App Store.

### 3. One Rust core

**Owner decision 4:** All cryptography, envelope and statement handling, OPAQUE, sync and merge, and URL matching stay in the Rust crates in `rizzy-vault`, and reach every native client through generated bindings. ADR 0013's principle "no TypeScript, Kotlin or Swift code implements cryptography …" is kept and extended to C# and C++. Rejected: re-implementing the security core per platform; for now, a hand-written C ABI with an `unsafe` exception; for now, an out-of-process core as the default. The C# and C++ generator routes are spiked first. If a spike fails, the question returns to the owner.

**Proposed:**
- **The rule, in this ADR's words:** no TypeScript, Kotlin, Swift, C# or C++ code implements cryptography, envelope or signed-statement handling, OPAQUE, sync or merge, or URL matching. It replaces ADR 0013 §1's sentence (§1).
- Every native client reaches `rizzy-client` through bindings generated in this repository, from a Rust binding crate on `lints.workspace = true`. `forbid` stays in every crate, and our own code gets no `unsafe` exception (ADR 0013 owner decision 1). Generator-emitted `unsafe` is audited third-party code under §4.1 (owner decision 7).
- A hand-written C ABI needs `#[unsafe(no_mangle)]` and raw pointers in our crate (V). It is not used without a new owner decision.
- ADR 0013 §3's rules 1–6 and 8 apply, as in force (ADR 0022 removes rule 2's pairing QR payload), to every binding crate and every host, and this ADR's rule 7 (§1.2) to the Rust crates; host code follows §4.5.
  - Keys stay in Rust behind opaque handles.
  - Only the named exceptions cross.
  - Plaintext crosses at the smallest useful size.
  - Errors are typed and carry no secrets.
  - Ciphertext crosses as opaque bytes.
  - The API is coarse.
  - The glue is generated.
  - Host input is untrusted.
- **Secrets cross as bytes.** Every named exception of rule 2 (master password, Secret Key, recovery code, export password, local unlock secret, share secrets and passphrase) crosses as a byte array, never as a string, so the host can zero its array after the call. This mirrors the web client's zeroed `Uint8Array` ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)). It removes the glue's own string copies. It does not remove the host's original, because typed input is a host string first.
- The local cache is a persistent format ([ADR 0011](0011-storage.md)), so it exists once, in Rust (§5; open question 6).
- `rizzy-ffi` moves from M7 to M3, when the first native desktop needs it (staging: open question 7). It stays a leaf crate over `rizzy-client` (ADR 0016 R2, R5 and R6, as §1.4 restates them).
- **One coarse API for every language.** Where one generator cannot express a shape (uniffi-bindgen-cpp has no async, V), the API avoids the shape for everyone rather than growing a per-language variant. Long calls are blocking calls that the host makes on a worker thread. For Linux, `rizzy-ffi-cpp` carries the same API in Diplomat's form (owner decision 9): a second surface to test and audit (§4.4).

### 4. Binding route per platform

| Platform | Route | Status |
|---|---|---|
| macOS, iOS | UniFFI Swift, first-party, in `rizzy-ffi` | Spike S1 builds the targets |
| Android | UniFFI Kotlin over JNA, first-party, in `rizzy-ffi` | Spike S1 |
| Windows | uniffi-bindgen-cs v0.11.0, in `rizzy-ffi` at the common pin (§4.3 (a)) | Owner decision 8; spike S2 |
| Linux | Diplomat, in `rizzy-ffi-cpp` (§4.4) | Owner decision 9; spike S3 |

#### 4.1 Rules for every generator

- **Pinned and vetted.** Every generator is pinned to an exact commit and built from vetted source in this repository's release workflow, with `--locked` against a `Cargo.lock` that this repository owns and reviews, bumped in its own PR. The generator's upstream lockfile is not used as is. Each generator gets an [ADR 0009](0009-crypto-dependency-policy.md)-style approval record: provenance, maintainers, open bugs, `unsafe` in its output, tests. The record is refreshed on every pin change. Third-party generators are installed from git, so cargo-deny never sees them, yet they write code that ships (A9).
- **One pin.** One exact UniFFI version serves every UniFFI generator in use. The third-party generators declare caret requirements (uniffi-bindgen-cs v0.11.0: `uniffi_bindgen = "0.31.0"`; PR #176: `"0.32.0"`, V), so the owned lockfile is what makes the patch versions match. Before generation, CI reads the generator's resolved graph (`cargo metadata` on the owned lockfile) and fails unless `uniffi_bindgen`, `uniffi_meta` and, if present, `uniffi_udl` equal the workspace's exact `uniffi` version.
- **Checks stay on.** Load-time contract and checksum checks stay on; `omit_checksums` is never set.
- **Generated once, reviewed as a baseline.** The core's release job produces the glue from the exact library it ships with (UniFFI library mode). The generated foreign glue for each language, and the macro-expanded binding crate, are committed as a reviewed baseline under the binding crate's directory (for example `crates/rizzy-ffi/generated/`). CI regenerates and fails on any difference from the baseline. That also checks determinism: uniffi-bindgen-cpp needs a fix or a sort for this (#65, V). Client repositories never regenerate or edit the glue; §7 enforces it.
- **Two checks on every generator, `uniffi` or toolchain bump,** each in its own PR:
  - (a) **The `forbid` build** for every shipped target, and the §10 tests. It catches `unsafe` in our code that keeps its span, re-spanned tokens, an emitted allow, and a rustc rule change (Context). It does not catch new or changed `unsafe` in generated code.
  - (b) **The baseline diff.** The PR shows the diff of the generated glue and of the expanded binding crate, with the counts of `unsafe` blocks, `extern` functions and `#[no_mangle]`/`export_name` items before and after. A reviewer signs it off like a crypto-crate diff (ADR 0009). The expansion needs a nightly toolchain (`cargo expand` relies on `-Zunpretty`, L), so it runs in a separate job on its own toolchain, like fuzzing (CRYPTO.md §15 item 7). Under owner decision 7, the expansion part of the baseline (the macro-expanded binding crate, not wasm-bindgen's JS output) covers `rizzy-wasm`. The JS output stays uncommitted, as ADR 0013 §4 "Build" says.
- **First-party `unsafe` token scan.** An xtask check lexes first-party `.rs` files and rejects the `unsafe` keyword token (comments and strings excluded). It turns S1's one-time "no `unsafe` token in our source" into a standing check, and it also covers `unsafe` that a macro would hide from the lint (Context).
- **Toolchains pinned.** Every toolchain that builds or links a shipped artifact is pinned, so a toolchain bump is a reviewed PR (§11).

#### 4.2 Swift and Kotlin

The first three bullets restate ADR 0013 §5 for this ADR (§1.2).
- First-party UniFFI. UniFFI is pinned to an exact version, the workspace pin of §4.1. Upgrades are deliberate PRs, handled like crypto crates (§4.1 (b)).
- The Kotlin and Swift packages are generated from `rizzy-ffi` in this repository's CI and release job (§4.1, §7).
- The iOS AutoFill extension uses the keychain-cached local unlock secret instead of running Argon2id ([THREAT_MODEL Q-13, AR-17](../THREAT_MODEL.md#10-open-questions-for-the-owner)). The memory footprint of `rizzy-ffi` inside the extension is measured in M7.
- Targets (V, rustc 1.94.1 platform-support page): `aarch64-apple-darwin` (Tier 1 with host tools); `x86_64-apple-darwin` (Tier 2 with host tools); `aarch64-apple-ios`, `aarch64-apple-ios-sim` and the Android targets `aarch64`, `armv7`, `x86_64` and `i686` (Tier 2 without host tools).
- JNA 5.12.0 or later (V), admitted on its Apache-2.0 option.
- Mobile HTTP stays in the host (ADR 0013 §2). Bitwarden's Rust-side HTTPS on Android needed hand-written JNI `unsafe` (V); keeping HTTP in the host avoids that.

#### 4.3 C# (Windows)

The options (open question 3; owner decision 8 chose (a)):

| Option | For | Against |
|---|---|---|
| **(a)** Pin UniFFI at the lowest version every UniFFI generator in use supports, today 0.31.2 (unyanked, 2026-06-17, V), and use the released v0.11.0 | A released generator. One binding crate and one pin for Swift, Kotlin and C#. UniFFI is not a workspace dependency yet, so nothing is downgraded | Swift and Kotlin run one minor behind upstream. Every later bump waits for the slowest generator: completed catch-ups took 1–5 months, and the lags open today run from about 3 to about 11.5 months (Context). 0.31.2 is the common pin only while Linux does not use uniffi-bindgen-cpp; with it, the pin is 0.29.4 until #66 lands or is pinned at a commit (#66 is a draft with no reviews that targets 0.31). The owned lockfile sets the patch version (§4.1). The `forbid` check must be re-run on 0.31.2. Whether v0.11.0 works with 0.31.2 is U. A UniFFI fix we need that lands only in 0.32+ would force (c) |
| **(b)** A second binding crate for C# on UniFFI 0.31.x, while `rizzy-ffi` stays on 0.32.x | Swift and Kotlin stay current | Two UniFFI versions in one lockfile (duplicate crates). Two binding surfaces to test and audit. A crate-table change. The same API maintained twice |
| **(c)** Stay on 0.32.x and build PR #176, or the nubo-db fork, at an exact commit | One current pin | Code upstream never reviewed: we carry a fork from day one. The PR's new `exclude` option can shift callback vtable slots with no diagnostic (V). The PR was last updated on 2026-09-04, before 0.32.1, and declares caret 0.32.0 (V), so the owned lockfile must be bumped to our pin |
| **(d)** Diplomat's .NET backend (Diplomat 0.16.1) | Off UniFFI's cadence. If Diplomat also serves Linux (§4.4), one second generator family covers both desktops, and UniFFI stays current for Swift and Kotlin | A very new backend: added on 2026-06-19 (L). A second bridge crate (`#[diplomat::bridge]`) carrying the same API: two binding surfaces to test and audit, the API maintained twice, a crate-table change. Compiles under `forbid`: L (read from source); its plain `#[no_mangle]` in our edition-2024 crates: U. Admitted by this ADR's rule 7 (§1.2) if chosen under open question 3; adds a third generator family |

In every option:
- This ADR's rule 7 (§1.2) admits the generator, and any fork or PR commit, only by the name the answer to open question 3 gives it. Any other needs a new ADR.
- `exclude` and `omit_checksums` are never used.
- The generated code lives in its own assembly, the only one with AllowUnsafeBlocks, and the only one that calls the native library. With uniffi-bindgen-cs this needs `access_modifier = "public"` (the default is `internal`, V). Whether that also makes the raw FFI layer public (RustBuffer, RustCallStatus, the native-method class) is U; S2 checks that the assembly's public surface is the typed API only, or the result goes back to the owner.
- The app projects keep AllowUnsafeBlocks off, and CI checks it. Whether a WinUI 3 app project builds and publishes (trimmed or AOT as intended) without it is U: CsWinRT's source generators may ask for it (review note, U). S2 checks; a failure goes to the owner (open question 5).
- Hand-written projects run a banned-API analyzer (§4.5).
- The generated C# is in M8 audit scope.
- The §10 tests run in our CI on GitHub-hosted windows-x64 and windows-arm64 runners, because upstream tests neither (V; availability of GitHub-hosted Windows arm64 runners to this repository: U).
- Strings, byte arrays and lists are limited to 2^31 bytes in uniffi-bindgen-cs (V). The core's size limits sit far below that.

C++/WinRT is a supported WinUI 3 language (V). It would let Windows share Linux's C++ binding, but it ties Windows to the Linux route, which is the least verified. Not recommended.

#### 4.4 C++ (Linux): Diplomat, gated on spike S3

No route from Rust to a Qt C++ host is verified under our rules today. Ranked as the research sheet ranks the in-process Qt routes (2026-09-26):

| Candidate | What we know | Standing |
|---|---|---|
| Diplomat 0.16.1 | MIT OR Apache-2.0; backends include C, C++ and .NET (V). The in-process option with the most established C++ backend; UniFFI's README points C and C++ users at it (V). Its own release cadence. Compiles under `forbid`: L, read from source. Its macro emits plain `#[no_mangle]`; whether our edition-2024 crates accept that: U. Costs: a second bridge crate carrying the API in Diplomat's form; two binding surfaces to test and audit; a crate-table change | Chosen, subject to S3 (owner decision 9), in `rizzy-ffi-cpp`. Admitted by this ADR's rule 7 (§1.2); adds a third generator family |
| uniffi-bindgen-cpp | 0.29.4 today, the slowest generator; 0.31 only in draft #66 (no reviews) or LiveKit's fork (L). No async (not needed, §3); no configuration in library mode; non-deterministic output (#65); C++20. Upstream CI runs Linux (with valgrind), MSVC and macOS (V). Not listed in UniFFI's README (V). Error, object and callback mapping: U. It keeps one binding crate and one API. Pinning #66 or LiveKit's branch at a commit means carrying unreviewed code as a fork from day one, the cost §4.3 (c) names | Second choice, run in S3 for comparison. Needs a common pin (§4.3 (a)): 0.29.4 today, 0.31.x only once #66 lands or is pinned. Not admitted by rule 7 (§1.2): moving to it takes a new ADR (owner decision 9) |
| safer-ffi | Claims FFI without `unsafe` in user code; C headers; 0.2 is a pre-release (V). Under `forbid`: U. Qt would need hand-written C++ wrappers over a C API | A lower-ranked candidate if S3 fails (the owner's choice) |
| cxx, cxx-qt (KDAB; cxx-qt 0.10.0, V) | Using Qt or C++ types from Rust needs hand-written `unsafe extern "C++"` blocks in our crate (V). Even extern-"Rust"-only bridges probably trip `forbid`, because the shims carry our spans (L). Errors reach C++ as strings, not typed codes (V) | Rejected: this ADR's rule 7 (§1.2, carried forward from ADR 0013) and CLAUDE.md's "no workarounds through FFI crates" |
| Out-of-process Rust helper | No generator. Keys stay outside the C++ address space, and a memory-corruption bug in the C++ host cannot reach the Rust heap. A new wire protocol, fuzz target and security boundary; hand-written C++ stubs | Not the default (owner decision 4). A candidate the owner may choose if S3 fails; it would need its own ADR |
| gtk4-rs (MIT, 0.11.5, V) | A Rust Linux client linking `rizzy-client` directly, with no generator. Under `forbid`: U. It reaches GTK through a large `-sys` binding stack, with `unsafe` inside third-party crates as in the `uniffi` runtime; that needs an owner ruling under "no workarounds through FFI crates", the rule that rejects cxx above. GTK is LGPL (L). Gives up Qt's styling control. Being Rust, it would live in this repository under §6, not in `rizzy-vault-linux` | A candidate only if the owner revisits Qt |

uniffi-bindgen-cpp's one advantage, a single binding crate and API, does not outweigh a fork from day one, the lowest pin in the family and no upstream endorsement. So Diplomat ranks first.

#### 4.5 Host-language `unsafe`

- CLAUDE.md's ban and `forbid` cover Rust crates. On the foreign side of every route, code can read or corrupt memory:
  - C#: the generated code needs AllowUnsafeBlocks (V). P/Invoke, `Marshal`, `System.Runtime.CompilerServices.Unsafe` and `MemoryMarshal` can do the same without it (L).
  - Kotlin: it calls through JNA's native dispatch (V).
  - Swift: the glue uses raw pointers (U); `unsafeBitCast`, `Unmanaged` and `OpaquePointer` do the same without the `Unsafe` prefix (L).
  - C++: there is no keyword. For this rule, host-language `unsafe` in C++ means manual lifetime management of binding handles, raw-pointer or buffer handling of values that cross the binding, `reinterpret_cast`, and `memcpy` on secrets.
- **Rule (owner decision 10): capability confinement.** Only generated binding code calls into the native library or uses these capabilities. Hand-written host code does not.
  - **C#:** only the generated assembly has AllowUnsafeBlocks, and only it calls the native library; CI rejects AllowUnsafeBlocks in any other project. Hand-written projects run a banned-API analyzer (for example Microsoft.CodeAnalysis.BannedApiAnalyzers, L) that bans `DllImport` and `LibraryImport`, `System.Runtime.InteropServices.Marshal`, `NativeMemory`, `System.Runtime.CompilerServices.Unsafe` and `MemoryMarshal`.
  - **Swift:** hand-written Swift uses no `Unsafe*` types, `withUnsafe*` calls, `unsafeBitCast`, `Unmanaged`, `OpaquePointer` or other `unsafe*` functions. Strict memory-safety checking is turned on if the pinned toolchain has it (SE-0458, U). App targets contain no C, Objective-C or C++ sources and no bridging headers, except listed exceptions. CI checks outside the generated package. That package is exempt only because §7 guarantees it is the attested, unedited glue. Sparkle's Objective-C is a dependency under §11, not hand-written code.
  - **Kotlin:** hand-written Kotlin uses no JNA or JNI API directly.
  - **C++ (`rizzy-vault-linux`):**
    - Generated code sits in one directory and is consumed from the attested archive (§7).
    - **One secrets module.** One reviewed module is the only hand-written C++ that may hold secrets: the rule 2 inputs (master password, Secret Key, recovery code, export password), the one-time Emergency Kit output, the rule 3 reveal output and the §5 clipboard callback. QML and other C++ pass values through it and never keep them. Inside it, secrets live in buffers it owns and zeroes after use; how to do that under Qt's implicit sharing is settled in M3 (U). No raw `char*` and no `memcpy` on secrets. `QString` lifetimes are kept as short as possible, since `QString` cannot be reliably wiped (U). CODEOWNERS review and a CI path check guard the module.
    - **No parsing of untrusted input in C++.** Imports, URLs and payloads go to the core as opaque bytes (rule 8). If C++ input handling is ever added, it needs a fuzz target (CLAUDE.md).
    - **Tests in `rizzy-vault-linux` CI:** the client's own tests and smoke suite under AddressSanitizer and UndefinedBehaviorSanitizer; static analysis (clang-tidy with the bugprone, cert and cppcoreguidelines checks, or similar; tool choice U) with warnings as errors.
    - **Release hardening:** `-D_FORTIFY_SOURCE=3` (with optimisation), `-D_GLIBCXX_ASSERTIONS`, `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection` on x86_64, PIE, and `-Wl,-z,relro,-z,now` (general knowledge, L). CI checks the release binary with a hardening checker (checksec or similar, U).

### 5. Host capabilities without a Rust host process

ADR 0013 §2 gave desktop a Rust host process: HTTP through a Rust client on rustls, SQLite, the OS keystore. With native UIs the process is C#, C++ or Swift, and the Rust library is loaded into it. Owner decision 11 places each capability as the Recommendation column says.

| Capability | A: in the Rust binding leaf | B: in the host | Recommendation |
|---|---|---|---|
| HTTP and TLS | The same Rust HTTP client as `rv` (chosen in M1, rustls only, [ADR 0009](0009-crypto-dependency-policy.md)). Keeps the rustls rule. On Linux it avoids Qt Network, whose OpenSSL backend loads the system OpenSSL at run time (V; that OpenSSL is the practical Linux backend, L), outside cargo-deny and the openssl ban. Less C++ near the plaintext. Costs: platform proxy and certificate settings are bypassed unless the client reads them, which is partly why ADR 0013 kept mobile HTTP in the host; a second I/O mode in the binding crate | .NET HttpClient, Qt Network, URLSession: platform proxies and trust stores. Costs: more TLS stacks outside our review, OpenSSL on Linux, and the host drives the effect loop | **Windows and Linux: A.** **Apple and Android: B**, as ADR 0013 §2 already says for mobile; macOS shares its Swift code and XCFramework with iOS |
| Local cache (SQLite) | sqlx with the `sqlite` driver in `rizzy-ffi`, or `rizzy-ffi-cpp` on Linux, which ADR 0016 R5, as §1.4 restates it, allows | Each host writes the cache format itself | **A everywhere.** The cache is a persistent format: one implementation, not five |
| Clipboard | A Rust clipboard crate in the leaf (not evaluated, U) | The host OS API | **B.** The core hands the value to one small host clipboard module through a callback interface, never to UI code, and never returns it (ADR 0013 §3 rule 3 and owner decision 3). The module sets the concealed hints (AR-16) and clears after 30 s by default, configurable (ADR 0015 owner decision 4, carried forward). It is the one mandatory callback through the third-party generators. S2 and S3 test it: repeated calls, an exception thrown inside the host callback, and the callback object's lifetime |
| Randomness, clock | getrandom in the leaf (ADR 0016 R2) | – | A, unchanged |
| Local-unlock key storage | – | The OS keystore API, under INV-62 | B, unchanged. Only the local unlock secret crosses (rule 2), as bytes (§3) |
| Core dumps off (INV-60) | The binding leaf's init (`rizzy-ffi` or `rizzy-ffi-cpp`) applies and asserts what it can: on Linux and Android, the dumpable flag and `RLIMIT_CORE` through rustix (safe API; THREAT_MODEL INV-60, V; the crate goes through ADR 0009) | The host disables dumps and crash-report upload at process start, before the core loads, where the platform allows it | **Both.** The host does it first. The leaf's init re-applies what it can and refuses to create a session handle if that fails. `rizzy-client` and the other R1 crates stay no-I/O (ADR 0016 R1). macOS and Windows mechanisms are confirmed in M3 (U). It applies to every native process, AutoFill extensions included, but it cannot close the crash paths below. Each client repository checks in CI that no crash-reporting SDK is linked |

**Crash capture the app cannot fully disable** (each U until confirmed in M3 or M7):
- Android: debuggerd's signal handler re-enables the dumpable flag at crash time so that `crash_dump` can attach, and writes a tombstone that includes memory near the registers (the review's reading of AOSP, U). Play vitals receives crash reports.
- iOS and macOS: system crash reports; Xcode Organizer.
- Windows: Windows Error Reporting, LocalDumps, Partner Center crash data.
- With `panic = "abort"` (THREAT_MODEL §6.4), every core panic becomes such a crash.
- Mitigations: key-holding allocations stay short-lived and zeroized; no crash SDK. Store-console crash data is readable by anyone who holds an AST-16 account. THREAT_MODEL gets an accepted-risk entry for this (On acceptance), because AR-10 says crash dumps "are disabled".

With A, the binding leaf drives `rizzy-client`'s state machine itself and exposes coarse blocking calls. With B, the host supplies the transport through a callback interface. The coarse API is the same either way; only the transport differs. A keeps HTTP, the most callback-heavy path, off the third-party generators. Spike S4 checks A on windows-msvc and linux-gnu. Bitwarden's `unsafe` was Android-specific (V); whether a desktop Rust TLS setup needs any first-party `unsafe` is U. Self-hosted servers with private CAs must still be reachable.

#### 5.1 Untrusted content on native clients

On every native client, the UI frameworks, text layout and image codecs parse input next to the keys ([Security trade-off](#security-trade-off)). The rules:

- **Images from the server or the network** are decoded in safe Rust in the binding leaf. That covers favicons from the `icons` role (M3) and any other image bytes. Hosts receive raw pixels of bounded dimensions (the limit is set in M3) and never pass those bytes to a platform image codec. A malicious server skips the `icons` role's re-encoding ([THREAT_MODEL §7.11](../THREAT_MODEL.md#711-icons-role-m3), A2), so the client decodes as if nothing had been re-encoded. The decoder crate goes through dependency review like any dependency with a security surface (chosen in M3, U).
- **No network sources in UI code.** No QML `Image` or `Loader` source, SwiftUI `AsyncImage`, WinUI `BitmapImage` URI or Compose image loader is a network URL. All network traffic goes through the one HTTP path of §5.
- **Text is plain text.** Every view that shows item, import, server or vault-member data renders plain text:
  - Qt: `textFormat: Text.PlainText` on `Text` and `Label`, and the plain-text format on editable fields. Qt's default, `Text.AutoText`, detects rich text, and the review reads Qt's documentation as saying that rich text can load images over the network (not re-read here, U). Enforced by a qmllint rule or a CI grep.
  - SwiftUI: `Text(verbatim:)`, never a `LocalizedStringKey` or Markdown built from data (general knowledge, U).
  - WinUI: `TextBlock`; no `RichTextBlock` for data (U).
  - Compose: `Text` with a plain `String`; no `AnnotatedString` built from HTML for data (U).
- **External links.** Links from item fields open in the system browser, and only for `http` and `https` (INV-42; ADR 0015 point 3, carried forward).
- **INV-35 on native clients.** No native client renders M5 share or M6 mail rich content, and none embeds a web view (WebView2, WKWebView, QtWebEngine, Android WebView), without an ADR. Shares and mail render as plain text until then.
- This section replaces ADR 0015 point 4's INV-35 rule (§1).

#### 5.2 Local data on native desktop clients

ADR 0015 point 9, carried forward word for word except its Windows Hello clause, which §2.1 replaces (§1.1). The last sentence of the third bullet is new.

- The encrypted cache lives in the app data directory and holds ciphertext only ([ADR 0011](0011-storage.md)).
- Device keys are wrapped under the account key.
- Biometric unlock (M3, Should) stores the local unlock secret in the OS keystore under [INV-62](../THREAT_MODEL.md#8-security-invariants): released only after an OS-enforced user-presence check, bound to hardware where available. That means the macOS Keychain with a Touch ID access-control flag. The exact APIs are confirmed in M3 (U). On Linux, Secret Service cannot enforce presence, so unlock falls back to the master password. On Windows, biometric unlock is out of scope until CRYPTO.md or an ADR specifies it (§2.1).
- Keys are zeroized on lock. There is no `mlock` (AR-10).

### 6. Repositories

**Owner decision 3:** `rizzy-vault-apple` (macOS, iOS, the AutoFill credential providers, the Safari extension wrapper if one is built), `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`. Web stays in `rizzy-vault`. With owner decision 4, all of the Rust core stays in `rizzy-vault`.

| Repository | Holds |
|---|---|
| `rizzy-vault` | All Rust: `rizzy-core`, `rizzy-sync`, `rizzy-proto`, `rizzy-client`, `rizzy-import`, `rizzy-match`, `rizzy-wasm`, `rizzy-ffi` and any binding crate, the server and `rv`. The web vault, the extensions and the share page (ADR 0014). Proposed in addition: generator pins, the generated-glue baseline, vector files, the design-token source, the dependency allow-list, the revocation denylist; ADRs, ROADMAP, THREAT_MODEL, CRYPTO.md and the disclosure process |
| `rizzy-vault-apple` | macOS and iOS apps (SwiftUI), the AutoFill credential providers, the Safari wrapper if one is built |
| `rizzy-vault-android` | The Android app (Kotlin), `AutofillService`, `CredentialProviderService` |
| `rizzy-vault-windows` | The WinUI 3 app (C#) |
| `rizzy-vault-linux` | The Qt 6 Quick app (C++ and QML) |

**Proposed:**
- **No Rust in a client repository.** No `Cargo.toml`, `.rs` or `build.rs`. Rust there would escape xtask, cargo-deny, cargo-vet and the workspace lints. CI in each client repository fails on any of them.
- **Client repositories hold only host UI and platform code, and consume only released core artifacts (§7).** They never patch the core, never regenerate glue, and never build the core with other flags. The one exception is the documented build-from-source path, which uses the same tag, flags and lockfile.
- A change that needs the core starts as a PR here.
- Design documents live only here. Client repositories link to them. A decision about a client repository is an ADR here.
- A repository is created when real code goes into it (ADR 0016 §6), not before.
- Each repository has CONTRIBUTING, a SECURITY.md pointing at the one disclosure process, branch protection, secrets and CI, and a licence and DCO/sign-off policy as ADR 0017 decides (§15 items 1–2). Store and signing credentials live only in the repository that uses them (A10).
- **Release hardening per platform** (ADR 0015 point 7, first half, carried forward). Release builds carry no debugger or inspector surface:
  - macOS and iOS: hardened runtime; no `get-task-allow` in release entitlements.
  - Linux: QML debugging compiled out (no `qml_debug` or `QT_QML_DEBUG`, no `QQmlDebuggingEnabler`); the QML debug server never enabled.
  - Android: `android:debuggable=false`; no WebView (§5.1).
  - Windows: Release configuration only; no debug-only diagnostic surfaces.
  - CI checks each release artifact for these. (Flag and API names: general knowledge, L.)
- **IPC surfaces** (ADR 0015 point 7, second half, and point 10, carried forward):
  - No native client registers a custom URI scheme or deep link without an ADR. Any such input is untrusted.
  - Integration between a native desktop client and the browser extension, such as unlocking the extension through native messaging, is a new IPC surface and needs its own ADR.

### 7. Artifact distribution

- This repository's release workflow runs only on tags that pass `git verify-tag` against a committed allowed-signers file, checked before any build step. A tag ruleset limits who can create tags, and the protected environment requires the owner's approval. It is a reusable workflow, called only by this repository. It builds each artifact once:

| Artifact | Contents | How the client pins it |
|---|---|---|
| XCFramework zip | iOS device and simulator, macOS arm64 and x86_64; generated Swift | A local Swift package with `binaryTarget(url:checksum:)` (V; that the checksum is SHA-256, L). The checksum covers the binary only, so the generated Swift ships only inside the attested zip. Client CI extracts it at build time into the package's source target; the repository keeps no editable copy, and CI fails if one appears. If S1 shows the glue can be compiled into the XCFramework as a module, that replaces the extraction |
| AAR | The Android targets, 16 KB-aligned; generated Kotlin | GitHub release URLs are not a Maven-layout repository. Proposed: a Gradle Ivy repository declared over the release URLs (a custom pattern layout, artifact-only metadata), so `gradle/verification-metadata.xml` pins its SHA-256 (feasibility U; checked in S1). Otherwise a CI step checks the SHA-256 and runs `gh attestation verify` on the download before Gradle runs, as for the nupkg. Gradle does not verify local file dependencies (V) |
| nupkg | win-x64 and win-arm64 libraries; the generated C# assembly | `packages.lock.json` in locked mode; a local feed filled by a verified download; Package Source Mapping (V) |
| C++ tarball | Linux x86_64 and aarch64 libraries, headers, generated C++ | CMake consumes the `URL_HASH`-checked archive directly (FetchContent or ExternalProject). CI rejects vendored copies of the generated sources |
| Extension bundle (only if Safari is built, §2.2) | The built `apps/extension` MV3 output, wasm core included | Same tag, SHA-256 and `gh attestation verify`. The Xcode wrapper imports it only after verification |
| Vectors bundle | The §10 smoke-test inputs and expected outputs | Same tag and checksum |
| Token bundle | Generated design tokens per toolkit (§13) | Same tag and checksum |

- Every artifact carries a SHA-256, build provenance from `actions/attest` (SLSA Build Level 2, Level 3 through a reusable workflow, V), an SBOM, the Rust notices file, and its tag and commit. Releases are immutable GitHub releases: assets cannot change and the tag is locked once published (V).
- Client CI verifies each artifact before building: `gh attestation verify <file> -R <owner>/rizzy-vault --signer-workflow <owner>/rizzy-vault/.github/workflows/<release>.yml --source-ref refs/tags/<tag> --deny-self-hosted-runners`. The flags exist; `-R` alone accepts an attestation from any workflow in the repository (V).
- **Revocation.** A denylist of revoked artifact digests and tags lives in this repository. Client CI checks it before building (§9.1).
- **Pull, not push.** A scheduled workflow in each client repository opens the bump PR, so the core holds no write token into client repositories. Bump PRs are never auto-merged (ADR 0009, Pinning and updates).
- **Build from source.** The path (pinned tag, `cargo build --locked`, the same flags) is documented and exercised in core CI. F-Droid needs it: it accepts only source builds, or FLOSS binaries from listed Maven repositories (V). So do Flathub and Corresponding Source.
- **Hosting:** GitHub Releases for every artifact (owner decision 14). GitHub Packages is not an option: its Gradle registry needs a token even to install public packages (V).
- `rust-toolchain.toml` lists only the wasm32 target, and core CI already runs its tests on `ubuntu-latest`, `macos-latest` and `windows-latest` (V, local: `.github/workflows/ci.yml`). Adding the Apple, Android, Windows and Linux targets to core CI, and the runners and jobs §10 needs beyond that matrix, is an explicit task (CLAUDE.md): Linux aarch64, Windows arm64, macOS x86_64 (`macos-latest` runs arm64, L), wasm32 under Node, an iOS simulator and an Android emulator.

### 8. Versioning and compatibility

- One semver per rizzy-vault release, covering the server, the bindings, the web vault and the extensions. The binding API is part of it; before 1.0 a minor release is breaking.
- Client apps keep their own versions and pin one exact core version with its checksum.
- A machine-readable compatibility matrix here lists, per client and store channel, the core version that is live. The release checklist reads it.
- **Readers before writers: recommended, not binding here.** Recommended for later changes to [ADR 0002](0002-own-protocol.md), [ADR 0004](0004-key-derivation-argon2id-secret-key.md) and [ADR 0007](0007-ciphertext-envelope.md), and for [ADR 0018](0018-item-record-encoding.md) while it is Proposed: a new `item_schema_version`, envelope `alg_id` or `kdf_id` is written only after every supported client in every channel ships a reader. The same goes for a new server-written response field that clients must understand. A new optional request field is gated by the server version, not by client readers. Today ADR 0002 point 3 lets clients ignore unknown response fields, and ADR 0004 point 8 adopts a new `kdf_id` at the next password entry; neither waits for readers. Until those ADRs change, this is a release-checklist item.
- The minimum client version in `/api/meta` rises only after the new client is live in its store (ADR 0002 point 5, unchanged).
- The UniFFI load-time checks catch a glue/library mismatch at run time. They are a tripwire, not a compatibility guarantee, and they say nothing about where the pair came from; §7's attestation does.
- Adding the core version to the `Rizzy-Client` header would change ADR 0002. Not decided here.

### 9. Cross-repository security releases

1. **The fix is prepared privately here.** CI cannot run in GitHub's temporary private advisory forks (GitHub's documentation, as quoted in the 2026-09-26 review: L). So the release workflow cannot build attested artifacts from one.
2. **No embargo mirror (proposed).** Pushing the signed core tag to this public repository discloses the fix: through the tag itself, and through Sigstore's public transparency log for the attestations (V). Under this proposal, store builds are exposed while they are in review; accepting this ADR accepts that exposure. Client repositories prepare release branches first. Each consumes the core artifacts of that tag and builds its own app in its own release workflow, with its own credentials (§6), never from a laptop. Client repositories never call the core's workflow or pass their secrets to it.
   - The alternative, a private mirror with its own release workflow and signer identity that clients accept for embargoed builds, shortens the exposure. It also adds a second identity that can produce artifacts every client trusts (A10), and a second release pipeline for one maintainer. Not proposed.
3. **Publish together, fast.** The core tag, its artifacts and the client releases go out as close together as store review allows. The proposed policy is to publish the Corresponding Source together with each binary, so no build ships without its source. Whether a delay would breach AGPL §6 (for example under the §6(b) written-offer route), and whether a store submission counts as conveying, is for ADR 0017's legal review (U).
4. `/api/meta`'s minimum version rises only after every store client with the fix is live (ADR 0002 point 5).
5. The advisory and the compatibility matrix name the fixed version of every client.

#### 9.1 Compromised artifact

- **Signal:** an attested artifact that was not built from a reviewed tag, or a compromised release credential.
- **Revoke:** add the digests and tags to the denylist (§7). Client CI refuses them.
- **Roll forward:** updaters never downgrade (§12), so a fixed release with a higher version supersedes the bad one on every channel. `/api/meta`'s minimum version rises once stores allow it, and the server refuses the bad version (`client_too_old`, ADR 0002 point 3).
- **Rotate:** the release environment's credentials, the tag-signing keys in the allowed-signers file, and any updater key reached (§12's rotation rule).
- **Advise:** the advisory names the affected digests and versions, and tells users what to do, including a manual reinstall on channels without an update path.

### 10. Tests

- **The full vector suite runs here, on every shipped target.** The CRYPTO.md §15 vectors run as Rust tests on Linux x86_64 and aarch64, macOS arm64 and x86_64, Windows x64 and arm64, wasm32 under Node, the iOS simulator and an Android emulator. Output must be byte-equal; a difference blocks the release.
- **Why not through the bindings.** ADR 0013 rule 6 forbids exporting `rizzy-core`'s primitives, and the fixed-nonce hook is `cfg(test)`-only (INV-12). A test-only binding would not be the shipped artifact.
- **Binding smoke tests run here, per language, against the exact artifact to be published:** XCTest (Swift), JVM plus an emulator (Kotlin), `dotnet test` on win-x64 and win-arm64 (C#), ctest under sanitizers (C++). They are coarse flows with deterministic outputs from the vectors bundle: open a fixed vault, decrypt a fixed item, log in against the simulated server, copy through the clipboard callback. An artifact is attested and published only if the vector suite and the smoke tests pass.
- **Client repositories** run a smoke subset against the pinned artifact, their UI and accessibility tests (high contrast included, §13), and end-to-end tests against a server image pinned by digest. `rizzy-vault-linux` also runs its own tests under AddressSanitizer and UndefinedBehaviorSanitizer, and static analysis (§4.5).
- CRYPTO.md §15 item 8 is extended on acceptance.

### 11. Dependency and supply-chain policy per repository

- **One allow-list, kept here** (ADR 0017 Decision 5, in whatever form ADR 0017 finally takes). Each client repository's licence gate reads the copy at its pinned core tag, and CI checks the copy is unchanged.
- INV-57 equivalents:

| Repository | Lock and verify | Advisories | Licence gate | Toolchain pins |
|---|---|---|---|---|
| apple | Zero third-party SwiftPM packages; CI checks `Package.resolved`. One proposed exception: Sparkle, for the direct-download macOS updater (§12) | Dependabot Swift alerts (V) | Manual review. OSV-Scanner does not read `Package.resolved` (V), and no licence tool was found | Xcode selected by exact version on a named macOS runner image. GitHub-hosted images update weekly, so the image itself is not pinned (L) |
| android | Gradle dependency locking plus a reviewed `verification-metadata.xml` with SHA-256/512 and PGP (V). Bootstrapping trusts whatever the repositories serve, so the first file is reviewed (V) | OSV-Scanner on the Gradle lockfile (V); Dependabot (V) | cashapp/licensee against the allow-list (V) | Gradle wrapper with `distributionSha256Sum`, and wrapper-jar validation in CI |
| windows | `packages.lock.json` with locked restore; Package Source Mapping with a repo-local `globalPackagesFolder`, because the mapping is skipped for packages already in the global folder (V) | NuGetAudit with NU1901–NU1904 as errors (V); OSV-Scanner | A NuGet licence tool (nuget-license or similar, L), plus a Windows App SDK exception if ADR 0017 grants one (§15 item 4) | `global.json` with an exact SDK version and `rollForward: disable` |
| linux | Per format. **AppImage:** Qt built from a pinned upstream Qt release tarball checked against its published checksum, or taken from a build image pinned by digest (the source is chosen in M3, U); the bundled Qt and its bundled C and C++ libraries (for example ICU, FreeType, HarfBuzz, image codecs) are listed in the client artifact's SBOM. **`.deb`:** the distribution's Qt as a declared dependency. **Flatpak** (later): a named KDE runtime branch, which its maintainers update in place. No other C++ packages; the core by `URL_HASH` | Qt's security advisories, and OSV or distribution trackers for the bundled libraries (sources L until checked). The AppImage is rebuilt and re-released on a Qt or bundled-library advisory. No usable gate exists for vcpkg or Qt (vcpkg writes SBOMs only; Conan's audit is experimental, V), so the set stays at Qt alone | A Qt module allow-list: LGPLv3 modules only, subject to ADR 0017 granting the Qt exception (§15 item 5); the 14 GPL-only modules banned | CMake and compiler versions fixed in a build image pinned by digest |

- **Core release workflow toolchains:** the Android NDK by exact version and checksum, r28 or later, which builds 16 KB-aligned by default (V); Xcode selected by exact version; the MSVC toolset and Windows SDK versions selected explicitly and recorded in the build log (full pinning on hosted runners: U); the Rust targets under the 1.94.1 pin.
- **Every repository:** Actions pinned by commit SHA; PR workflows get no secrets; no crash-reporting SDK (INV-60); Dependabot PRs reviewed and never auto-merged.
- **The binding generators** live only in this repository's release workflow (§4.1).
- **One workflow hits every client.** A compromise of the core release workflow now reaches every client through the artifacts. That is why §7 verifies tag signatures, uses a reusable workflow, a protected environment, attestations pinned to the workflow file and immutable releases, and why §9.1 exists.

### 12. Updaters (INV-55)

| Platform | Channel | Verification |
|---|---|---|
| macOS | Sparkle for Developer ID builds: EdDSA (ed25519) signatures, added through SwiftPM (V). The Mac App Store, if ADR 0017 allows it (§15 item 3) | The EdDSA public key is compiled in |
| Windows | **Before signing:** no in-app installer. The app fetches a version manifest from a compiled-in URL, verifies its ed25519 signature against a compiled-in key before it shows anything, and opens only a compiled-in release page, never a URL from the manifest. The user downloads and replaces the app by hand; the app does not verify that download. **After signing:** the Microsoft Store, if ADR 0017 allows it (§15 item 3), or MSIX with App Installer | Manifest: ed25519 against the compiled-in key, in a signed-statement format that CRYPTO.md specifies before the Windows client ships (ADR 0007 point 8). Builds, after signing only: Authenticode, or Store signing |
| Linux | A signed apt repository for `.deb`; AppImage updates (mechanism chosen in M3, U); Flathub later | A signature from the pinned release identity |
| iOS, Android | App Store (§15 item 3), Google Play (§15 item 9), each subject to ADR 0017 | Store signing |

- **Per channel,** ADR 0015 point 8's rules carry forward:
  - An update without a valid signature is refused.
  - The updater never installs a version lower than the current one.
  - The private key stays offline (a hardware token or an offline machine), or in a protected CI environment that only release tags can use.
  - Key rotation: a new key ships inside an update signed by the old key.
  - Key loss: if the key is lost, users must reinstall manually, and the docs say so.
- Before Windows signing, INV-55 holds only because nothing is installed. The alternative is a verified in-app updater for unpackaged builds, in Sparkle's model; no Windows candidate was evaluated (U), and it costs a third-party dependency or our own installer code.
- The self-contained Windows build bundles the .NET runtime and the Windows App SDK runtime. Their security fixes reach users only through our releases (Risks).
- INV-55's test becomes per platform, including the pre-signing manifest check and the compiled-in URL.

### 13. Design system and accessibility

- **Tokens are shared; components are not.** The token source lives here (`packages/ui`, [ADR 0014](0014-ui-stack.md) §5). The release job generates token files per toolkit (CSS custom properties, Swift, Kotlin for Compose, a XAML resource dictionary, a QML singleton) and ships them as the token bundle (§7). The generator is chosen in M3. Recommendation: an `xtask` subcommand, so no new toolchain is needed.
- Each client builds its own components from the tokens. A native client hard-codes no colour, size or font; review enforces it.
- **WCAG AA contrast** is checked on the declared token pairs in this repository's CI (ADR 0014 §5). That check does not cover pairs a client combines in its own components, or the platforms' contrast modes. So each client:
  - uses token pairs only as declared, and covers its own combinations by review or a client-side contrast check;
  - respects the platform's contrast modes. Hard-coded colours or styles that block theme-resource lookup break XAML high contrast (V). So the generated XAML dictionary uses ThemeDictionaries (Light, Dark, HighContrast) with the HighContrast entry mapped to system colour resources, or it leaves the system theme brushes untouched when high contrast is on. SwiftUI respects Increase Contrast; Compose respects high-contrast text; Qt follows the platform palette or high-contrast theme (U each).
- Keyboard-only use and screen-reader labels are built and tested per toolkit: UI Automation peers for custom WinUI controls (V), the `Accessible` attached property on custom QML items (V), and the SwiftUI and Compose accessibility APIs. Each client repository has an accessibility test job, including a high-contrast or increased-contrast check, before its first release.

### 14. Audit scope (M8)

- The M8 audit covers this repository at tag T and each client repository at a commit pinned to T. A client outside that set is labelled unaudited at v1.0.
- Scope this ADR adds:
  - five native host codebases: INV-55, INV-60, INV-61, INV-62, INV-68 (as amended), the §5.1 untrusted-content rules, autofill, clipboard, keystore;
  - the C++ secrets module and hardening in `rizzy-vault-linux` (§4.5);
  - the generated glue in each language, the `uniffi` runtime, and the expansion baseline (§4.1);
  - each third-party generator's templates;
  - JNA's native dispatch library;
  - each updater integration, and the Windows manifest check.
- THREAT_MODEL §7.3 per platform (On acceptance) is the auditor's map.

### 15. Licensing items ADR 0017 must decide (listed, not decided)

ADR 0017 was deferred when this ADR was drafted (owner decision 5), and was Accepted on 2026-09-27 without these items. A new ADR that partially supersedes it must decide or update:

1. **The licence of each client repository.** Decision 1 covers "this repository" only. Every client build is still a combined work with the AGPL core.
2. **DCO and the sign-off check** in every repository.
3. **The §7 App Store permission across repositories.** Wording that covers the combined work; committed here and in each client repository before the first external code contribution to either; whether it must also cover the Mac App Store and the Microsoft Store, which may apply from M3, not M7 as ADR 0017's App Store rows assume. Apple's terms apply its Standard EULA unless the provider supplies its own licence (V); whether an AGPL custom EULA settles §10 is U. Microsoft's Store policies have no open-source-specific rule (L).
4. **The Windows App SDK licence.** The NuGet package, unlike the MIT GitHub repository, is under Microsoft Software License Terms. They require distributors to bind end users to terms that protect Microsoft, to indemnify Microsoft, and not to make the SDK subject to a source-disclosure licence (V). Whether AGPL's System Library exception covers it, and whether those terms are "further restrictions", is U, for the lawyer before the Windows client ships. A NuGet licence gate built from the allow-list fails on it without a documented exception.
5. **Qt.** An LGPLv3 exception for the Linux client, since Decision 5 bans third-party LGPL. Dynamic linking and relinking. Qt's source in the release archive for a bundled AppImage (L). The 14 GPL-only modules banned. Qt's tools are GPLv3 with the Qt exception (V). Qt itself warns that "online application stores may have rules that are in conflict with LGPL" (V).
6. **Other licences.** JNA on its Apache-2.0 option (V). The licence of code generated from MPL-2.0 templates (U). Sparkle's licence (MIT, L).
7. **Licence gates, and their timing.** Decision 5 names only JS, Swift and Kotlin, and dates the Swift and Kotlin gates to M7. The Swift gate (macOS), a NuGet gate (Windows) and a C++/Qt module gate (Linux) are needed from the first M3 release of each client.
8. **Corresponding Source per client release:** the client tag, the core tag, vendored crates and ecosystem sources, merged notices (Decision 7's desktop and mobile rows). §9's publish-together policy depends on the answer.
9. **Google Play and F-Droid.** Google Play's clause that its developer agreement prevails over the developer's EULA (not read at the source, U). F-Droid's source-build rule (V).
10. **SPDX headers.** Decision 6 lists Rust, TypeScript/JavaScript, Swift, Kotlin, shell, CSS and HTML templates. It should also name C#, C++, QML and XAML and build scripts, or say that it applies to every source file in every client repository.
11. **Stale wording.** Decision 1's "desktop shell", and the Context's "M3 | Desktop releases (Tauri)" and "natively in desktop (ADR 0015)", should name the native clients and this ADR.

### Owner decisions (2026-09-26)

Given in chat on 2026-09-26.

1. **Web platforms stay in this repository:** React and strict TypeScript for the web vault and the Chrome/Firefox MV3 extensions; the M5 share recipient page is framework-free TypeScript (ADR 0014 answer 2, unchanged).
2. **Desktop and mobile clients are native, not webviews:** Windows = WinUI 3 with C#/.NET; Linux = Qt 6 with Qt Quick/QML, chosen over GTK for control over the look; macOS = SwiftUI; iOS = SwiftUI; Android = Kotlin. This reverses ADR 0014 answer 3 (desktop reuses `apps/web`, recorded earlier the same day) and replaces Accepted ADR 0015 (Tauri).
3. **Repositories per platform toolchain:** `rizzy-vault-apple` (macOS, iOS, the AutoFill credential providers, and the Safari extension wrapper if one is built), `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`. Web stays in `rizzy-vault`.
4. **One Rust core.** All cryptography, envelope and statement handling, OPAQUE, sync and merge, and URL matching stay in the Rust crates in `rizzy-vault` and reach every native client through generated bindings. ADR 0013's principle "no TypeScript, Kotlin or Swift code implements cryptography …" is kept and extended to C# and C++.
   - Re-implementing the security core per platform is rejected.
   - For now, a hand-written C ABI with an `unsafe` exception is rejected, and so is an out-of-process core as the default.
   - The C# and C++ generator routes are spiked first. If a spike fails, the question returns to the owner.
5. **ADR 0017 stays deferred.** This ADR lists what it must cover (§15) and decides none of it.
6. **Partial supersession (open question 1).** A new ADR may supersede named sections of an Accepted ADR, through ADR 0020, a small successor to ADR 0001. The older ADR's status becomes "Partially superseded by ADR NNNN (§x, §y)". Everything not named stays binding. This ADR therefore supersedes ADR 0015 in full and partially supersedes the named parts of ADR 0013 and ADR 0016 (§1). The owner chose this over restating ADRs 0012, 0013 and 0016 in full (ADR 0012 for [ADR 0018](0018-item-record-encoding.md)'s changes).

### Owner decisions (2026-09-27)

The owner accepted this ADR on 2026-09-27 and answered open questions 2–10 as recommended:

7. **Generator-emitted Rust `unsafe`** (open question 2) → Accepted as audited third-party code, like any dependency with `unsafe` inside (ADR 0009 item 5), under §4.1's controls: the committed expansion baseline, a reviewed diff with counts on every generator or toolchain bump, and the first-party `unsafe` token scan. Our own code gets no exception. No separate ADR: the corrections to ADR 0013 Risks and ADR 0016 R7 and §5 stay in §1.2 and §1.3, and bind from this acceptance, for `rizzy-wasm` (M1) too.
8. **Windows binding route** (open question 3) → (a), subject to S2: `rizzy-ffi` at the lowest UniFFI version every UniFFI generator in use supports, 0.31.2 today, with the released uniffi-bindgen-cs v0.11.0. No extra crate. The pin moves only when every UniFFI generator in use supports the next minor. If a UniFFI fix we need lands only in a newer minor, the question re-opens with (c). If S2 and S3 both pass with Diplomat, (d) is weighed then.
9. **Linux binding route** (open question 4) → Diplomat, subject to S3, in one `#[diplomat::bridge]` crate. Its name, `rizzy-ffi-cpp`, is this ADR's resolution of the draft's ⟨B⟩ placeholder, not part of the answer. The answer brings the §1.3 row that partially supersedes ADR 0009's "RNG rules", third bullet. If Diplomat fails S3, the route returns to the owner (owner decision 4). uniffi-bindgen-cpp, the second choice that S3 also runs, would change §1 and the common pin (§4.3 (a)), so it takes a new ADR.
10. **Host-language `unsafe`** (open question 5) → Yes for generated glue, under §4.5's capability confinement. No by default for a framework-required AllowUnsafeBlocks in a hand-written project; if S2 shows WinUI needs it, the question returns with the exact requirement.
11. **Host capabilities** (open question 6) → As §5 recommends: HTTP in the Rust leaf on rustls on Windows and Linux, in the host on Apple platforms and Android; SQLite in the Rust leaf everywhere; the clipboard through one host module behind a callback; INV-60 in the host and in the leaf's init. `rizzy-ffi` and `rizzy-ffi-cpp` hold what falls to the leaf on the platforms they serve (§1.2, §1.4).
12. **Staging and the macOS AutoFill provider** (open question 7) → M3 ships the macOS client. Windows and Linux follow once S2 and S3 pass, each as its own ROADMAP row; whether they stay v1.0 Musts is the owner's ROADMAP call (ROADMAP §7). A macOS AutoFill provider joins ROADMAP as a Should in M7 with iOS, with passkeys only once INV-64's amendment covers it.
13. **Windows biometric unlock** (open question 8) → Deferred until a CRYPTO.md design exists (§2.1).
14. **Artifact hosting** (open question 9) → GitHub Releases for every artifact. F-Droid, if wanted, through the build-from-source path. Maven Central only if third parties are to consume the bindings.
15. **Safari** (open question 10) → Not in M3. The key-custody ADR comes first (§2.2), with Safari's wasm CSP support checked in it; the extension then ships with the Apple repository's M7 work or later.
16. **Spikes.** The owner accepted this ADR before any spike ran: S1, S4 and S5 have not run, and S2 and S3 need Windows and Linux runners. Each result is recorded later as a dated `## Amendments` entry, and a failed spike returns to the owner (On acceptance, Spikes).

### On acceptance

These edits follow this ADR's acceptance, in changes the owner approves. None is made in this ADR. Replacement text in quotes is written for its target file; links are added when the edit is made.

**ROADMAP (owner approves):**
- **§3 M3:** "Design system, desktop app, quick-access search, …" → "Design system (shared tokens; React components for web), native desktop app(s), quick-access search, …", naming macOS (owner decision 12).
- **§3 M7:** "iOS/Android apps with OS autofill, passkey (WebAuthn) storage and use." → "Native iOS (SwiftUI) and Android (Kotlin) apps in their own repositories, over the Rust core through UniFFI, with OS autofill, passkey (WebAuthn) storage and use."
- **§4.1** workspace row: drop `rizzy-desktop`; `rizzy-ffi` from M3; add `rizzy-ffi-cpp` with the Linux client; cite ADR 0016 together with this ADR, which partially supersedes it. New Must row, M3: "Client repositories per ADR 0019 (`rizzy-vault-apple`, `-android`, `-windows`, `-linux`): attested core artifacts, no Rust outside `rizzy-vault`".
- **§4.3** biometric row, "Unlock with biometrics / OS keychain on desktop & mobile": add "Windows: deferred until a CRYPTO.md design exists (ADR 0019 §2.1); Linux: master password only (INV-62)" (owner decision 13).
- **§4.4** Safari row: not in M3; after its key-custody ADR, with the Apple repository's M7 work or later (owner decision 15).
- **§4.5** design-system row → "Design system: tokens (color, spacing, type), light/dark, shared by every client as generated token files; React component library shared by web vault + extension; native components per toolkit, from the same tokens".
- **§4.5** desktop row → "Desktop apps, native per OS: SwiftUI (macOS), WinUI 3 (Windows), Qt 6 Quick (Linux), over the Rust core through generated bindings (ADR 0019)": macOS in M3; Windows and Linux each in its own row once S2 or S3 passes, with the priority the owner sets, since ROADMAP §7 makes every Must a v1.0 blocker (owner decision 12).
- **§4.5** accessibility row: add "(per toolkit on native clients, platform contrast modes included)".
- **§4.10:** a macOS AutoFill provider row: Should, M7, with passkeys only once INV-64's amendment covers it (owner decision 12).
- **§5** Client core → "Shared Rust `core` → wasm (web/extension) + generated bindings for every native client (UniFFI Swift/Kotlin; C# and C++ per ADR 0019) + native (CLI)". UI stack → "TypeScript + React for web vault and extensions (ADR 0014); native toolkits for desktop and mobile (ADR 0019)". Desktop → "Native per OS: SwiftUI, WinUI 3, Qt 6 Quick"; Why: "native look and OS integration, no webview IPC surface; costs in ADR 0019".
- **§6.2** gains: "Five native UIs plus the web UI. None of the comparable password managers ships three native desktop UIs." A new risk: "The Windows and Linux clients depend on third-party binding generators that lag UniFFI; the Linux route is unverified (ADR 0019 §4)."

**THREAT_MODEL:**
- **§3.1:** the Desktop row becomes native per OS, with code from signed releases per platform; the Mobile row names the separate repositories; the Distribution channels row gains the new channels.
- **§3.2** diagram: "desktop Tauri (signed rel.)" → native desktop clients, signed releases per platform.
- **§3.3 TB-10** → "On every native client, mobile included, the Rust core runs in the host's process. TB-10 is an audit boundary only, as in the browser. 'Keys stay on the Rust side' is an API rule (ADR 0013 §3), not a memory boundary. This corrects the earlier 'process or IPC boundary' wording for mobile. A C++ host adds memory corruption in the key-holding process (§7.3)."
- **§7.3** rewritten per platform (Windows/C#, Linux/C++, macOS/Swift). Drop the webview XSS and IPC rows. Add: generated-glue bugs at the FFI boundary; memory corruption in the C++ host, with §4.5's mitigations; platform decoders and rich-text sinks as memory-corruption and exfiltration surfaces (§5.1); icon cache poisoning by a malicious server; INV-35 on native clients; QML only from `qrc`; release-build debug surfaces per platform (§6); the per-platform updater and the Windows pre-signing manifest check; Windows Hello scoping (out of scope for now); the clipboard module; OS crash capture (§5). If the heading changes, the three `#73-desktop-app-tauri-m3` links in ADR 0015 are fixed (ADR 0001 point 4).
- **§7.4:** the §5.1 untrusted-content rows for mobile.
- **A9:** the Swift, Gradle, NuGet and Qt ecosystems; binding generators as build-time supply chain that cargo-deny does not see; the core release workflow as the one compromise that reaches every client; the toolchains (NDK, Xcode, MSVC and the Windows SDK, the Gradle wrapper, the .NET SDK, Qt, CMake) pinned per §11; for `.deb` and Flatpak builds, distribution packagers and the Flathub/KDE runtime maintainers supply code that runs in the key-holding process.
- **A10 and AST-16:** Microsoft Partner Center; the Windows code-signing identity (OV Authenticode certificate or Azure Artifact Signing account) and the MSIX signing identity; the Windows release-manifest key (§12); Apple Developer ID and notarization; the Sparkle EdDSA key; the apt repository signing key and the AppImage update key; the Google Play upload key; App Store Connect API keys; the tag-signing keys in the allowed-signers file (§7); Flathub; Maven Central and its PGP key if chosen; per-repository CI secrets; no cross-repository write tokens. AST-16's singular "desktop updater key" becomes "per-channel updater keys (ADR 0019 §12)".
- **A14:** replace "(Tauri support is unverified; to be checked in M3)" with a rule that each native desktop excludes its window from screen capture where the OS supports it. Mechanisms, each U until M3: `SetWindowDisplayAffinity` on Windows, `NSWindow.sharingType` on macOS; Linux under Wayland is likely unsupported. Add desktop input methods and OS text services to the input-field leak list.
- **AST-22 and the §8.10 traceability row:** "ADR 0015 §9" → "ADR 0019 §5.2, which carries forward ADR 0015 point 9".
- **§7.17:** the new channels, and artifact attestation from M3, ahead of M8's provenance for images.
- **INV-35:** its mechanism on native clients: plain text, no web view (§5.1).
- **INV-55:** per-platform updater, per-platform test, including the Windows pre-signing manifest check.
- **INV-57:** the per-repository equivalents of §11, the generator pins and the toolchain pins.
- **INV-60:** every native process, host-language executables and AutoFill extensions included; the binding leaf's init check, scoped to what it can assert; a no-crash-SDK check in each client repository. Plus a new accepted-risk entry (or a change to AR-10): OS crash capture the app cannot disable (§5), with `panic = "abort"` turning core panics into crashes; short-lived, zeroized key-holding allocations as mitigation; store-console crash data readable through AST-16 accounts.
- **INV-62:** Windows Hello unlock out of scope until a CRYPTO.md design exists (owner decision 13).
- **INV-64:** note that OS credential providers (Android, iOS and macOS; owner decision 12) receive only a `clientDataHash`, not `clientDataJSON`, and that Google tells providers to skip the origin-to-RP-ID check (V). INV-64's scope "(extension or mobile)" and its "calling-app verification on mobile" must widen to every OS provider. Any allowlist of privileged browsers or calling apps ships as a signed build input and is never fetched from the server. The invariant must be amended before M7. That is an owner decision on an invariant; this ADR does not make it.
- **INV-68:** a native-desktop clause. Secret fields use the toolkit's password control (WinUI `PasswordBox`, SwiftUI `SecureField`, a QML `TextField` with `echoMode: TextInput.Password` and input-method hints that mark the text sensitive and turn prediction off; exact flags U, confirmed in M3). Spell-check, autocorrect and prediction stay off on reveal, and a revealed secret is shown read-only. Where the toolkit allows it, the typed secret is not exposed to input-method frameworks (IBus and Fcitx behaviour: U). The test column becomes "per-toolkit UI tests in each client repository". If the owner reads this as a change to the invariant rather than to its mechanism, it is flagged like INV-64.
- **SECURITY.md**, in the same PR: the official-sources list and the scope cover all five repositories.

**CRYPTO.md:**
- **§1 goal 6** → "runs unchanged on native, wasm32 and through the generated bindings of ADR 0019 §4. No crypto is re-implemented in TypeScript, Kotlin, Swift, C# or C++."
- **§4.2** keystore-unlock row: the ADR 0015 reference becomes ADR 0019 §5.2.
- **§10.2:** a signed release-manifest statement for the Windows pre-signing version check (§12), specified before the Windows client ships (ADR 0007 point 8).
- **§12.1:** "Tauri shell, UniFFI bindings" → "native binding crates (ADR 0019 §4)".
- **§12.2** Limits: host-language strings (.NET, Swift, Kotlin, `QString`) cannot be wiped, like JavaScript strings. The buffers the generated glue and the binding runtime use to pass values across the boundary are freed without wiping, on the Rust side and in each host language (for UniFFI, `RustBuffer` frees and the foreign lowering buffers). A `Zeroizing` type cannot cross the boundary; only the copy that stays in Rust is wiped. Secrets cross as bytes, so the host can zero its array (ADR 0019 §3).
- **§15 item 8** → "natively on every shipped target (Linux, macOS, Windows, the iOS simulator, an Android emulator) and as wasm32 under Node; plus binding smoke tests in Swift, Kotlin, C# and C++ against the exact release artifact (ADR 0019 §10)".

**ADRs and repository files (status lines are the owner's act, ADR 0020 points 3 and 9):**
- ADR 0015 → "Superseded by [ADR 0019](0019-native-clients.md)". Nothing else in it changes (ADR 0020 point 3). If THREAT_MODEL §7.3's heading changes, its three anchor links are fixed (ADR 0020 point 4).
- ADRs 0013, 0016 and 0009: each status line gains the entry drafted in §1, after any earlier entry. Nothing else in them is edited: no marker, no note (ADR 0020 point 9).
- [README](README.md) (the owner's act):
  - The Status cells of rows 0013, 0016 and 0009, each repeating its new status line; row 0015, `Superseded by [0019](0019-native-clients.md)`; row 0019, `Accepted`.
  - Row 0013's Milestone cell "M1 (wasm, CLI) / M3 (Tauri) / M7 (UniFFI)" → "M1 (wasm, CLI) / M3 (native desktop bindings) / M7 (UniFFI)", matching the Milestone line restated in §1.2.
  - The gate "Before desktop work in M3: 0015 Accepted" → "0019 Accepted. For Windows (Linux): spike S2 (S3) recorded as passed, in an ADR 0019 `## Amendments` entry, for the route of ADR 0019 owner decision 8 (9); or, after a failed spike, an Accepted ADR that records the replacement route".
- CLAUDE.md, wording approved by the owner: the ADR status sentence; the crate-boundary summary (binding crates are leaf crates; no Rust in client repositories); the `unsafe` rule, for generator-emitted glue as audited third-party code under §4.1 (owner decision 7).
- SECURITY.md line 125: its ADR status sentence ("ADRs 0001–0013, 0015 and 0016 were accepted on 2026-09-25; …"), brought up to date together with CLAUDE.md's.
- The xtask rules table, the tests that restate it (`rows_match_adr_0016`, the directory-name and leaf checks in `rules.rs`) and the cargo-deny wrappers, per §1.4: `rizzy-desktop` removed; `rizzy-ffi` from M3 and `rizzy-ffi-cpp` added. The xtask `unsafe` token scan (§4.1).
- A new ADR that partially supersedes ADR 0017: the §15 items.

**Follow-up ADR changes, not made by this ADR:**
- ADRs 0002, 0004, 0007 and 0018: §8's readers-before-writers rule, if the owner wants it binding.

**Spikes** (ADR 0020 point 6: outside `crates/`, on 1.94.1, with results cited in this ADR). None ran before acceptance (owner decision 16). S2 and S3 gate Windows and Linux desktop work through the README gate above.
- **Spike results are amendments this ADR provides for** (ADR 0020 point 4). When a spike is run, its result is appended as a dated entry under a final `## Amendments` section of this ADR, in its own PR approved by the owner. The entry states pass or fail against the table below, the route tested and a link to the spike record, and nothing else. It does not change §1, the binding crate names or the owner decisions.
- **A failed spike** returns its question to the owner (S1: owner decision 16; S2, S3: owner decision 4; S4 re-opens owner decision 11). A replacement route is recorded in a new ADR, even one that rule 7 (§1.2) would admit, because choosing it changes owner decision 8 or 9.

| Spike | What | Pass | Fail |
|---|---|---|---|
| S1 Swift and Kotlin | A crate shaped like `rizzy-ffi`, under command-line `forbid`, exporting records, enums, error enums, objects, callback interfaces and bytes, at the candidate pin (0.31.2, and 0.32.2 for comparison). Built for the §4.2 targets; Swift and Kotlin generated; the crate expanded; a smoke flow run. Also: whether the Swift glue compiles into the XCFramework as a module, and whether the AAR resolves through a Gradle Ivy repository over release URLs | Every target builds with no `unsafe` token or lint allow in our source, exact compiler output recorded. The expansion is recorded with its counts of `unsafe` blocks, `extern` functions and `no_mangle`/`export_name` items. Smoke outputs byte-equal to native. The Android `.so` and JNA's `libjnidispatch.so` are 16 KB-aligned. The secret copies left after a call are recorded per generator | Any target needs `unsafe` in our source, an output differs, or alignment fails → the question returns to the owner |
| S2 C# | The same crate at 0.31.2 with uniffi-bindgen-cs v0.11.0 (and PR #176 at 0.32.x for comparison), and the same API through Diplomat's .NET backend, for `x86_64-` and `aarch64-pc-windows-msvc`. Generated C# in its own public assembly, consumed by a minimal WinUI 3 app on Windows App SDK 2.x with AllowUnsafeBlocks off | Builds under `forbid`. The generator's resolved `uniffi_bindgen` and `uniffi_meta` equal the pin. Smoke flow byte-equal on win-x64 and win-arm64. Error enums work. The clipboard callback works when called repeatedly, when the host callback throws, and across the callback object's lifetime. Checksums on, no `exclude`. Two generation runs identical. The generated assembly's public surface is the typed API only. The WinUI app project builds and publishes with AllowUnsafeBlocks off and no CsWinRT diagnostic asking for it. Secret copies recorded | A crash or undefined behaviour at the boundary, a mismatch, any need for `omit_checksums` or `exclude`, raw FFI types in the public surface, or a WinUI app project that needs AllowUnsafeBlocks → the question returns to the owner (open questions 3 and 5) |
| S3 C++ | Diplomat 0.16.x and uniffi-bindgen-cpp (#66, or LiveKit's 0.31 branch) at the common pin, each under `forbid`, for `x86_64-` and `aarch64-unknown-linux-gnu`, consumed by a minimal Qt 6 Quick app | At least one candidate builds under `forbid` (edition 2024) with no `unsafe` in our source; for uniffi-bindgen-cpp, the resolved `uniffi` crates equal the pin; typed errors reach C++ as codes; objects and callbacks work; output is deterministic; the smoke flow is byte-equal and clean under ASan and UBSan; secret copies recorded | Neither passes → the question returns to the owner (owner decision 4). Candidates, none pre-chosen: safer-ffi, the out-of-process helper, gtk4-rs, or another route |
| S4 Desktop host capabilities | `rv`'s HTTP client on rustls and sqlx-sqlite inside the binding leaf, for windows-msvc and linux-gnu. INV-60 through rustix on Linux; the macOS and Windows mechanisms | Builds under `forbid` with no first-party `unsafe`; trusts the platform store or a user-added CA; the INV-60 assertions pass; mechanisms identified | First-party `unsafe` needed, or no workable trust story → owner decision 11 (open question 6) re-opens |
| S5 `forbid` probes | A cxx extern-"Rust" bridge, a `#[cxx::bridge]` containing a hand-written `unsafe extern "C++"` block, a safer-ffi export and a minimal gtk4-rs window, each under `forbid` | Exact compiler output recorded, turning today's L and U findings into V | – (informational) |

## Consequences

### Positive

- No webview: no XSS-to-IPC class, no CSP or capability allow-list to maintain on desktop, and no three rendering engines to test.
- Native OS integration: the platform look, the platform accessibility APIs, AutoFill providers on macOS and iOS from shared SwiftUI code, and the Keychain. Mac users notice native UX (V: the reaction when 1Password dropped it).
- The security core stays one implementation. The M8 audit still covers one crypto, one sync and one cache implementation.
- macOS and iOS share one repository, one XCFramework and one signing pipeline.
- Store and signing credentials are split per repository (A10). Core PR CI needs no Qt, .NET or Xcode.
- Client repositories hold no Rust, so the Rust policy boundary (xtask, cargo-deny, `forbid`) stays whole.
- Generated code gets a reviewed baseline on every bump, which the `forbid` build alone never gave (§4.1).

### Negative

- **Five native UIs plus the web UI,** where ADR 0015 planned one desktop UI built from the web UI.
  - ADR 0015 called three native desktop UIs "impossible at our size". ROADMAP §6.1 and §6.2 say M1–M3 is already a serious year and that clients are the real cost.
  - None of the comparable password managers ships three native desktop UIs. 1Password stopped its SwiftUI Mac app and chose not to build a native Windows one; Dashlane dropped desktop at five platforms; the native desktops that exist (KeePassXC, Enpass) are one Qt codebase (tags as in Context).
  - 1Password found that SwiftUI shared less between iOS and macOS than it expected (V).
- **ROADMAP §4.5's design-system Must becomes tokens plus per-toolkit components.** Every component, and the WCAG AA work including contrast modes, is built four more times: WinUI, Qt, SwiftUI, Compose.
- **Three desktop host languages,** each with its own keystore, clipboard, hotkey and updater glue.
- **FFI arrives in M3 instead of M7.** Windows depends on a third-party generator; Linux has no verified route.
- **The UI frameworks of every platform parse untrusted input in the key-holding process.** §5.1 limits what they see. It costs a Rust image decoder and plain-text discipline in five codebases.
- **A C++ host** puts memory-unsafe code in the process that holds the keys. §4.5's secrets module, sanitizers, static analysis and hardening are extra work in `rizzy-vault-linux`.
- **Every generator bump** needs a reviewed baseline diff and a nightly expansion job (§4.1).
- **Governance.** Five repositories, each with a licence and DCO policy (ADR 0017), SECURITY.md, branch protection, secrets, CI, Dependabot and a supply-chain gate, for a solo maintainer (AR-12). A protocol change is a multi-repository change, the reason ADR 0016 rejected separate repositories. Feature parity has to be tracked across repositories.
- **CI cost:** the runners and jobs §7 lists (Linux aarch64, Windows arm64, macOS x86_64, wasm32 under Node, an iOS simulator, an Android emulator) in core CI for artifacts and vectors, plus each client repository's own runners.
- More release credentials (AST-16), and a supply-chain gate and toolchain pins per ecosystem.
- Corresponding Source, notices and SBOMs span repositories.
- Windows biometric unlock waits for a CRYPTO.md design; ROADMAP §4.3's Should is not met on Windows until then (open question 8).
- Before Windows signing, users update by hand, and the app does not verify the download (§12).
- A security fix is public from the moment the core tag is pushed, while store builds are still in review (§9).

### Risks

- **Generator stall or drift.** uniffi-bindgen-cs's only maintainer seen acting on PRs merged the last upgrade after a self-described shallow review and says he lacks time for proper reviews (V; maintainer count U). uniffi-bindgen-cpp is three minors behind (V). Signal: a UniFFI fix we cannot take, or a generator bug in our shapes. Response: carry a fork, or re-open owner decisions 8 and 9.
- **The pin is held back** by the slowest UniFFI generator, and the lag compounds with each UniFFI minor.
- **rustc changes the external-macro rule,** or a generator re-spans tokens. Every binding build then fails in its own PR. That is the intended failure, but it can block a release.
- **A spike fails** (S2, S3). Windows or Linux then has no native client until the owner picks a route. Until then those users have the CLI, the Chrome/Firefox extension and the web vault.
- **Licensing.** The Windows App SDK terms (V) or Qt's LGPL (V) may not pass legal review, and ADR 0017, as accepted, does not cover them yet (§15).
- **Platform churn.** Windows App SDK 2.x servicing ends 2027-04-29, and 3.0 will be a side-by-side package family (V). Open-source Qt means following the one-year minors (V).
- **Bundled runtimes.** The self-contained Windows build bundles the .NET runtime and the Windows App SDK runtime, so their security fixes reach users only when we release. Signal: an advisory for either. Response: an out-of-band release within a time set in M3.
- **Crash capture.** The OS crash paths of §5 can write key-holding memory to disk or to a store console.
- **Signing eligibility** for Azure Artifact Signing (V).
- **Passkeys in OS credential providers** (Android, iOS, and macOS if added) need an INV-64 amendment before M7.
- **The iOS AutoFill memory cap** (L) against `rizzy-ffi`'s size, which is unmeasured.
- **Schedule.** If M3 slips because of three desktops, M5–M8 slip with it. Signal for a new ADR: a desktop client that has not shipped two milestones after its spike passed.

## Alternatives considered

- **Keep Tauri** (ADR 0015). One desktop UI from the web UI, keys in a Rust process, no FFI on desktop. The owner chose native look and integration over a webview. Tauri's main threat, webview XSS reaching IPC, is the one native UIs remove.
- **Electron.** The same UI reuse; the core can run as wasm (Bitwarden's monorepo depends on its wasm SDK, V). Rejected for the same reason, plus a bundled browser engine to patch.
- **One Qt codebase for all three desktops** (KeePassXC, Enpass). One desktop UI instead of three. But the C++ route is the unverified one, it would put C++ on every desktop, and the owner chose each OS's own toolkit.
- **C++/WinRT on Windows,** sharing Linux's C++ binding. One route for both, but Windows then depends on the least verified route (§4.3).
- **The security core re-implemented per platform.** Dashlane's Apple code does its crypto with CommonCrypto and CryptoKit (V); no core shared with its Android code was found (U). Rejected by the owner and by ADR 0013: several implementations to audit and keep identical.
- **A hand-written C ABI with an `unsafe` exception** (Bitwarden's `bitwarden-c`, V). Rejected by the owner for now. It needs `#[unsafe(no_mangle)]` and raw pointers in our crate (V).
- **An out-of-process Rust core** driven by the native UI over inherited pipes. No generator lag. Its gains: keys stay outside the host's address space, a memory-corruption bug in the host cannot reach the Rust heap, and no third-party generator sits in the boundary. But it is a new wire protocol and security boundary: a fuzzed parser, stubs per language, relock on crash, two signed binaries per platform. Against same-user malware it adds little. On Linux a non-dumpable process (INV-60) cannot be read by a same-user caller without CAP_SYS_PTRACE, in either design (ptrace access-mode checks, V). On macOS and Windows no such protection is claimed for either design (U). NG-1 stands. Not the default for now (owner decision 4); a candidate the owner may choose if a spike fails.
- **cxx and cxx-qt.** Rejected on policy (§4.4).
- **interoptopus for C#** (0.16.5; C# is Tier 1, actively maintained, V). The most mature C#-first generator found that is independent of UniFFI's cadence; Diplomat's .NET backend and csbindgen are independent too. But it is C#-only, a third generator family (not admitted by §1.2's rule 7, so only through a new ADR), and untested under `forbid` (U). A candidate the owner may choose if S2 fails.
- **csbindgen (V) or cbindgen (L).** Both need hand-written `#[unsafe(no_mangle)]` exports. Rejected.
- **gtk4-rs for Linux.** No generator, but the owner prefers Qt, and its `-sys` stack needs a ruling (§4.4).
- **A private embargo mirror** for security releases. Not proposed (§9): a second trusted signer identity and a second pipeline.
- **Native clients in this repository** (ADR 0016 §7). One lockfile, one PR per protocol change. Rejected by owner decision 3. The Rust-side advantages survive, because all Rust stays here.
- **One desktop repository and one mobile repository.** It would split macOS from iOS, which share SwiftUI code, the XCFramework and signing. Rejected by owner decision 3.

## Open questions for the owner

None open. Question 1 was answered on 2026-09-26, questions 2–10 on 2026-09-27, as recommended.

1. **How do the partial changes to ADR 0013 and ADR 0016 take effect?** → [Owner decision 6](#owner-decisions-2026-09-26).
2. **Generator-emitted Rust `unsafe`** → [owner decision 7](#owner-decisions-2026-09-27).
3. **The Windows binding route** → owner decision 8.
4. **The Linux binding route** → owner decision 9.
5. **Host-language `unsafe`** → owner decision 10.
6. **Where desktop HTTP, SQLite, the clipboard and INV-60 live** → owner decision 11.
7. **Milestone staging, and the macOS AutoFill provider** → owner decision 12.
8. **Windows biometric unlock** → owner decision 13.
9. **Artifact hosting** → owner decision 14.
10. **The Safari extension** → owner decision 15.

## References

- [ADR 0001](0001-record-architecture-decisions.md) points 3, 4, 5 and 6; [README](README.md) (lifecycle, gates); [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession) point 9; [ADR 0022](0022-server-mode-only.md) §1 (its parts of ADRs 0013 and 0016)
- [ADR 0002](0002-own-protocol.md) points 3 and 5; [ADR 0004](0004-key-derivation-argon2id-secret-key.md) point 8; [ADR 0007](0007-ciphertext-envelope.md) point 8; [ADR 0009](0009-crypto-dependency-policy.md) ("RNG rules", owner decision 1); [ADR 0011](0011-storage.md); [ADR 0013](0013-shared-client-core.md); [ADR 0014](0014-ui-stack.md); [ADR 0015](0015-desktop-tauri.md); [ADR 0016](0016-workspace-layout.md); [ADR 0017](0017-licensing.md); [ADR 0018](0018-item-record-encoding.md)
- [ROADMAP](../ROADMAP.md) §3, §4.1, §4.3, §4.4, §4.5, §4.10, §5, §6, §7
- [THREAT_MODEL](../THREAT_MODEL.md) §3.1, §3.2, §3.3 (TB-10), §6.4, §7.3, §7.4, §7.11, §7.17, §8.10, NG-1, A2, A9, A10, A14, AST-16, AST-22, INV-12, INV-35, INV-41, INV-55, INV-57, INV-60, INV-62, INV-64, INV-68, AR-10, AR-12, AR-16
- [CRYPTO.md](../CRYPTO.md) §1 (goal 6), §4.2, §10.2, §12.1, §12.2, §15 items 1, 7 and 8; [CLAUDE.md](../../CLAUDE.md)
- Local files read 2026-09-26 (V): `Cargo.toml` (no uniffi dependency yet), `rust-toolchain.toml`, `deny.toml`; the `git grep` reference search and `wc -w` Decision counts of ADRs 0009, 0013 and 0016 as accepted (§1.5); `crates/xtask/src/rules.rs` and `check.rs`
- Native-clients research sheet, 2026-09-26. Primary sources read that day, with the confidence tags used in the text:
  - UniFFI: crates.io version list; the mozilla/uniffi-rs README, docs and Kotlin bindings template (V).
  - uniffi-bindgen-cs: repository, releases, README, `CONFIGURATION.md`, CHANGELOG, `cs.yml`, `Cargo.toml`, PRs #141, #163 and #176, open issues and PRs (V); the nubo-db fork (L).
  - uniffi-bindgen-cpp: tags, README, CHANGELOG, `cpp.yml`, PRs #59, #62 and #66, issue #65 (V); the LiveKit fork (L).
  - rustc 1.94.1 source: `rustc_lint/src/builtin.rs`, `rustc_middle/src/lint.rs`, `rustc_span/src/hygiene.rs` (V); `levels.rs` (L); the 1.94.1 platform-support page (V).
  - cxx book and cxx-qt book and examples (V); cxx `expand.rs` (L); Diplomat, interoptopus, safer-ffi, csbindgen, gtk4 on crates.io and in their repositories (V, with the `forbid` behaviour and the Diplomat .NET backend date L or U as stated). cbindgen: general knowledge (L).
  - Microsoft Learn: Windows App SDK release channels and 2.0 notes, WinUI 3 overview, deployment, MSIX signing, accessibility, `KeyCredential` and `KeyCredentialManager`, P/Invoke source generation (V); a Q&A answer on Hello credential scoping (L); the Microsoft.WindowsAppSDK 2.5.1 licence (V); Microsoft Store policies (L).
  - Qt: releases, licensing, LGPL obligations, UI technology comparison, Quick Controls customisation, Qt Quick accessibility, Wayland, SSL (V); GNU LGPLv3 text (V; our reading of §4(d), L).
  - xdg-desktop-portal GlobalShortcuts and Secret; Flatpak runtimes; QtKeychain (V).
  - Apple developer documentation: multiplatform targets, `ASCredentialProviderViewController`, `ASPasskeyCredentialRequest`, Safari web extensions, packaging and messaging (V); Apple Media Services Terms (V); the iOS AutoFill memory cap (L).
  - Android developers: autofill services, credential provider, androidx.credentials and Compose releases, 16 KB page sizes (V); the JNA licence (V).
  - Precedent: 1Password blog posts (V) and support page (V; toolkit names L); Adam Caudill's personal blog on 1Password 8 (V that he says so); Six Colors (V); Bitwarden sdk-internal, ios, android, clients and sdk-sm repositories (V); Proton Pass repositories (V); KeePassXC (V); Enpass (V, L as stated); Dashlane blog and repositories (V); libsignal and Signal-iOS (V).
  - Supply chain: GitHub artifact attestations and the Sigstore public transparency log, immutable releases, `gh attestation verify`, GitHub Packages Gradle registry (V); Maven Central requirements, F-Droid inclusion policy, OSV-Scanner, Gradle dependency verification, cashapp/licensee, NuGetAudit, Package Source Mapping, vcpkg SBOM, Conan audit (V); Dependabot ecosystems (V, L as stated); SwiftPM binary targets (V; SHA-256 L); Sparkle (V; licence L); Android NDK r28 16 KB default (V).
- From the 2026-09-26 review of this draft, not in the research sheet, tagged as stated in the text:
  - GitHub temporary private forks cannot run CI (GitHub documentation as quoted in the review, L).
  - UniFFI `RustBuffer` frees without zeroing (`uniffi_core/src/ffi/rustbuffer.rs` as read by the review, L).
  - Qt `Text.AutoText` and remote images in rich text (U); Android debuggerd re-enabling the dumpable flag and tombstone contents (U); CsWinRT source generators and AllowUnsafeBlocks (U).
  - Text APIs of SwiftUI, WinUI and Compose (U); screen-capture exclusion APIs and input-method hints (U); Swift strict memory safety, SE-0458 (U); Microsoft.CodeAnalysis.BannedApiAnalyzers (L); compiler and linker hardening flags (L); checksec and clang-tidy as tools (U); `cargo expand` needing nightly (L).
  - .NET 8's end of support (U); GitHub-hosted Windows arm64 runners (U); GitHub-hosted runner image updates (L); a Gradle Ivy repository over release URLs (U).
