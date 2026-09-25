# ADR 0017: Licensing and contribution terms

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M0 (must be Accepted before the first external code contribution is merged)

## Context

ROADMAP §4.1 (Must, M0) asks for: "License policy: AGPL-3.0 server/core; decide client license; dependency license allow-list".

**Current state of the repository (V, read from the files):**

- `LICENSE` holds the verbatim GNU AGPL version 3 text (19 November 2007). It adds no project notice and does not say "only" or "or any later version".
- `Cargo.toml` `[workspace.package]` declares `license = "AGPL-3.0-only"`. All four crates inherit it (`license.workspace = true`) and are `publish = false`.
- `README.md` has no license statement.
- No source file has an SPDX header.
- No DCO or CLA has been decided. [CONTRIBUTING.md](../../CONTRIBUTING.md) asks for an interim `Signed-off-by` on every commit until this ADR is decided.
- `deny.toml` enforces a dependency license allow-list, listed in Decision 5. `[licenses.private] ignore = true` exempts our own crates from that check.

**Version selection is declared in one place only.** AGPL §14 (V, `LICENSE`): "If the Program does not specify a version number of the GNU Affero General Public License, you may choose any version ever published". Today the version choice is stated only in Cargo metadata. It needs to be stated where a human reads it.

**Copyright ownership decides what the project can do later.**

- **The owner is bound only for code others wrote.** A copyright holder is not bound by the license it grants on its own code. While the owner has written all the code, the owner can distribute it on any terms: through the Apple App Store, under a commercial license, or under a later license. Once other people's contributions are in the tree, the owner is a licensee of that code and bound by the AGPL for it, like everyone else.
- **Every holder must agree to a change.** Relicensing, adding an exception, dual licensing, and moving from "only" to a later version each need permission from every copyright holder of the affected code.
- **Only holders can enforce the license** against someone who violates it.
- **The choice is only free before outside code arrives.** Contribution terms fixed before the first external code contribution cost nothing. Changing them afterwards means asking every past contributor for consent, or rewriting their code.

**Distribution channels on the roadmap:**

| Milestone | Channels |
|---|---|
| M1 | Container image, release binaries (`rizzy-vault`, `rv`), web vault served by the `web` role |
| M2 | Chrome Web Store and Firefox AMO |
| M3 | Desktop releases (Tauri) and an updater feed |
| M7 | Apple App Store and Google Play |
| M10 | "Licensing/billing hooks" for business features. ROADMAP §4.9 calls managed hosting a separate business decision |

**The App Store problem.**

- Apple's App Store terms put usage rules on recipients. The widely held reading, including the FSF's, is that these rules are "further restrictions", which AGPL §10 forbids. AGPL §12 then says that if you cannot meet both sets of obligations, you "may not convey it at all" (license text V; the FSF's position U, not re-read in this session).
- VLC for iOS was pulled from the App Store in January 2011 after one of VLC's GPL copyright holders complained (U).
- In practice:
  - Any single contributor can object to an AGPL app that contains their code being on the App Store.
  - A third party, such as a fork or a packager, can never lawfully put it there without permission from every copyright holder.
- The AGPL §6 "Installation Information" rules for User Products are a second argument that is sometimes raised (U, legal interpretation).
- No comparable conflict is known for Google Play, F-Droid, Chrome Web Store or AMO (U). The obligation there is to make the Corresponding Source of each exact build available.

**The core decides the client license question.** `rizzy-core` is AGPL (ROADMAP) and is linked into every client:

- as wasm in the web vault and extension ([ADR 0013](0013-shared-client-core.md));
- through UniFFI on mobile;
- natively in desktop ([ADR 0015](0015-desktop-tauri.md)) and the CLI.

So every distributed client is a combined work that contains AGPL code, whatever license its own UI code carries. **A client license choice cannot remove the App Store problem. Only permissions from the copyright holders can.**

## Decision

### 1. One license for the whole repository

- Everything in this repository is licensed AGPL-3.0, with the version chosen as in Decision 2. That covers:
  - the server, `rizzy-core`, `rizzy-sync` and `rv`;
  - every future crate;
  - the web vault, browser extension, desktop shell and mobile app code.
- **The client UI code gets no separate license.** A more permissive UI license would buy third parties little, because the core they must link is AGPL anyway. It would also double the compliance story.
- **Non-code assets.**
  - Icons and illustrations we create follow the code license, unless the M3 design-system decision says otherwise.
  - Bundled third-party fonts and icons keep their own licenses (for example SIL OFL-1.1) and ship with their license texts.
  - 1Password's assets and trade dress are never used (ROADMAP §4.5, Won't).
- **Trademarks.** The AGPL grants no trademark rights. A trademark policy comes with the public product name, which ROADMAP §6.9 says must be decided before M8.

### 2. `AGPL-3.0-only`, stated explicitly (owner to confirm)

| Option | What it means | For | Against |
|---|---|---|---|
| **AGPL-3.0-only** (declared today) | Only v3 applies | The owner, not a third party, controls the terms. Manifests stay as they are. | Moving to a future AGPLv4 needs consent from every copyright holder, unless a CLA exists |
| AGPL-3.0-or-later | Recipients may choose any later FSF version (§14) | A future version can be adopted without chasing contributors. Our own later releases can still narrow to "only"; the reverse is impossible without consent | Delegates future terms to the FSF, and nobody knows what a v4 would say. We are not aware of any AGPLv4 work (U) |
| AGPL-3.0-only plus a §14 proxy | The owner (or a later foundation) is named as the proxy who can accept future versions | Keeps the upgrade path inside the project without a CLA | There is no standard SPDX id, so it needs a `LicenseRef-` expression, which SBOM tools and license scanners handle poorly. KDE is reported to use this model (U) |

**Recommendation: keep `AGPL-3.0-only`.** The flexibility "or later" buys is speculative. Control over the terms is concrete. If the owner wants a path to future versions without a CLA, use the §14 proxy instead of "or later".

Whichever option is picked:

- `LICENSE` stays the verbatim text, so license detectors keep working.
- The README gets a "License" section that states the version choice in words, names any additional permission (Decision 3), and says "Copyright the rizzy-vault contributors; see the git history".
- The same SPDX expression appears in `Cargo.toml` and in every file header (Decision 6).

### 3. An App Store additional permission, added before the first external code contribution

- **What.** A GPLv3/AGPLv3 §7 "additional permission" for the whole program. It allows conveying the covered work through distribution platforms whose terms add usage restrictions, such as the Apple App Store, on the condition that the Corresponding Source of that exact build is available under the AGPL.
- **How it spreads.** Under §7, additional permissions on the whole program "shall be treated as though they were included in this License". Contributions made under inbound = outbound terms (Decision 4) then carry it automatically.
- **Timing.** It must be in place before the first external code contribution is merged. Documentation does not ship in app builds, so documentation PRs do not need it. Adding it after external code has landed needs every code contributor's consent.
- **Downstream.** §7 lets downstream recipients remove the permission from their copies. We do not merge code from a fork that removed it.
- **Wording.** The text is drafted and reviewed by a lawyer before it is committed. This ADR is not legal advice.
- **SPDX.** The exact SPDX expression for a custom addition is to be confirmed (U). Our crates are `publish = false` and excluded from cargo-deny's license check, so this affects only SBOM and scanning tools.

### 4. Contribution terms: DCO recommended, CLA if dual licensing is wanted (owner decides)

| | DCO 1.1 (`Signed-off-by`) | CLA: a license grant with relicensing rights, not an assignment | Copyright assignment |
|---|---|---|---|
| What the contributor gives | A certification that they have the right to submit the code under the project license (inbound = outbound) | A broad license to the owner, including the right to sublicense and relicense | Ownership |
| Friction | `git commit -s` | Sign once through a bot or form. Deters some contributors, notably security researchers and drive-by fixers | Highest. Needs paperwork and in practice a legal entity |
| Relicense or add exceptions later | Only with every contributor's consent | Owner can | Owner can |
| M10 business edition | All-AGPL, or proprietary modules written **only** by the owner, kept separate from community code | Dual licensing of all code is possible, e.g. a commercial license for SMBs that want no AGPL obligations | Same as CLA |
| App Store (M7) | Works only with the Decision 3 permission in place from day one | Owner can submit without it | Owner can submit |
| Trust signal | Strong: the owner cannot take the code proprietary | Weaker. Companies have used CLA rights to move to non-open licenses (e.g. HashiCorp, 2023; U) | Weakest |
| Tooling | A CI check that every commit has a `Signed-off-by` line | A CLA bot and a signature record | Legal process |

**Recommendation: DCO, plus the Decision 3 permission, plus an all-AGPL M10.**

- For a zero-knowledge password manager, being verifiably unable to close the code is part of what we sell.
- The one concrete distribution need, the App Store, is solved by Decision 3.
- ROADMAP scopes M10 as features of the same product, not a separate proprietary edition.

**When to pick a CLA instead:** if the owner wants to keep the option to sell community-contributed code under non-AGPL terms (dual licensing or an open-core business edition). In that case, pick the CLA now, as a license grant with a written promise that the code stays available under the AGPL. A CLA cannot be imposed retroactively. It covers earlier contributions only from contributors who sign it; the rest are rewritten.

**Until this ADR is Accepted:**

- Contributors add `Signed-off-by` to every commit ([CONTRIBUTING.md](../../CONTRIBUTING.md)).
- If the owner picks a CLA, contributors whose code was merged before that are asked to sign it, or their code is rewritten.
- A CI check for sign-offs is a separate change that lands with acceptance; M0 does not change CI. The check covers the PR's commits and also verifies that the squash commit on `main` keeps the trailers.
- Only a human signs off. AI coding agents never add `Signed-off-by`; the human who opens the PR adds it after review ([CLAUDE.md](../../CLAUDE.md)).

**Keeping the DCO record in `main` (owner action, repository settings).** The DCO record is the `Signed-off-by:` trailers, and authorship is the `Co-authored-by:` trailers. A squash merge keeps them only if the squash commit message includes the commit messages.

- Current settings (V, GitHub API, 2026-09-25): merge commits, squash merging and rebase merging are all enabled; squash title = "commit or PR title"; squash message = "commit messages"; sign-off on web-based commits is not required.
- Set the squash default to "Pull request title and commit details" (API: title `PR_TITLE`, message `COMMIT_MESSAGES`). Never "Pull request title" or "Pull request title and description": both drop the commits' `Signed-off-by:` trailers from `main`.
- Disable merge commits and rebase merging, since [CONTRIBUTING.md](../../CONTRIBUTING.md) describes squash-only.
- Enable "Require contributors to sign off on web-based commits".

### 5. The dependency license allow-list is `deny.toml`

- CI runs `cargo deny check` (with `--all-features`, which `[graph] all-features = true` in `deny.toml` also sets). A dependency whose license expression is not satisfied by this list fails CI:

  | License | Typical use / note |
  |---|---|
  | MIT, MIT-0 | Most of the ecosystem |
  | Apache-2.0 | Most of the ecosystem. Compatible with (A)GPLv3 in one direction only |
  | Apache-2.0 WITH LLVM-exception | e.g. `blake3`, licensed `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception` (crates.io, V) |
  | BSD-2-Clause, BSD-3-Clause | e.g. the dalek crates, `subtle` |
  | ISC | Misc crates |
  | Zlib | Misc crates |
  | CC0-1.0 | e.g. `blake3` |
  | Unicode-3.0 | Unicode data crates |
  | MPL-2.0 | e.g. `uniffi`, `webauthn-rs`. File-level copyleft, compatible via MPL §3.3. `MPL-2.0-no-copyleft-exception` is **not** allowed |
  | CDLA-Permissive-2.0 | Data licenses, such as bundled root-certificate lists (U: which crate uses it) |
  | AGPL-3.0-only, AGPL-3.0-or-later | Affects third-party crates only: our own crates are skipped by `[licenses.private] ignore = true`. The only effect of these two entries is to let third-party AGPL crates pass CI. See open question 6 |

- Other `[licenses]` settings in `deny.toml`:
  - `confidence-threshold = 0.93`
  - `exceptions = []`
  - `unused-allowed-license = "allow"`
  - `[licenses.private] ignore = true`
- **Not allowed, and why:**
  - GPL-2.0-only: incompatible with (A)GPLv3.
  - GPL-3.0 and LGPL (any version): third-party copyleft is not covered by the Decision 3 permission or by a CLA. Only the holder of that code can grant either, so one such crate in a client build blocks App Store distribution (M7) and any later relicensing. License compatibility is not the reason: GPL-3.0 combines with AGPL through §13, and shipping complete Corresponding Source already meets LGPL's relinking requirement. Adding either takes an amendment and a per-crate `exceptions` entry.
  - Third-party AGPL: same reason. `deny.toml` currently lets it through (see the table and open question 6).
  - SSPL, BUSL and Commons Clause: not open source.
  - Crates with no license at all.
- **Changing the list** is an amendment to this ADR (ADR 0001 point 4). The PR states the crate that needs the license and why. A per-crate `exceptions` entry is preferred over widening `allow`. `deny.toml`'s own header rule applies too: "Changing this file is a security decision: it needs a reason in the PR description."
- **Beyond Rust.** `cargo deny` covers Rust only. Before the first JavaScript dependency lands (web vault, M1), CI must get an equivalent license gate over the JS lockfile with the same allow-list. The tool is chosen with the UI stack ([ADR 0014](0014-ui-stack.md)). The same applies to Swift and Kotlin dependencies in M7.

### 6. SPDX identifiers

- Every source file we write starts with the SPDX line on its first line, or on the line after a shebang. That covers Rust, TypeScript/JavaScript, Swift, Kotlin, shell, CSS and HTML templates:

  ```text
  // SPDX-License-Identifier: AGPL-3.0-only
  ```

  (The comment syntax changes per language, and the expression follows Decision 2 and 3.)
- **No per-file copyright lines or years.** Authorship is recorded in git history, and the README carries the project copyright statement.
- Crate manifests keep `license.workspace = true`. A crate never overrides it.
- Files that cannot carry comments (JSON, lockfiles, images) are covered by the repository-level statement. Full REUSE compliance (`REUSE.toml`, `reuse lint`) is optional and can come in M8 along with the SBOM.
- **When the headers land.** The six existing scaffold source files (four under `src/`, plus `tests/cli.rs` in `rizzy-cli` and `rizzy-server`) get their headers in the first M1 code PR; M0 changes no Rust source. A CI check for missing headers lands with the first product code.

### 7. Third-party notices and source offers in every release artifact

- **Notices.** Permissive licenses (MIT, BSD, ISC, Apache-2.0) require their copyright and license texts to ship with binaries. Apache-2.0 §4(d) also requires reproducing the dependency's `NOTICE` file, if it has one. Zlib requires its notice only in source distributions; the notices file lists Zlib crates anyway, for completeness.
- **The notices file.** Every artifact carries a generated third-party notices file. It lists each dependency's name, version and license, with the full license texts.

  | Artifact | Where the notices go |
  |---|---|
  | Server binary and OCI image | Release archive; a fixed path in the image |
  | `rv` | Release archive |
  | Web vault and extension | A bundled file plus an "Open-source licenses" view. It covers npm packages *and* the Rust crates compiled into the wasm |
  | Desktop | Bundle and About screen |
  | Mobile | In-app licenses screen |

- **Generated in the release job, never maintained by hand.** It is built from `Cargo.lock` and the JS lockfile. Candidate tool: `cargo-about` (not evaluated in M0, U). The release job fails if generation fails or finds a license outside the allow-list.
- **Source offer.** Each release links to its exact tag and attaches a complete source archive: the tagged tree plus the source of every dependency compiled into the release artifacts. That is the `cargo vendor` output for the Rust crates and the package tarballs named in the JS lockfile.
  - Why vendored: a tag archive does not contain the crates statically linked into our binaries or compiled into the wasm/JS bundles. We read AGPL §1 ("all the source code needed to generate ... the object code and to modify the work") as including them. MPL-2.0 §3.2 (e.g. `uniffi` in the mobile apps) also requires its source to be made available to recipients of the executable, with directions for getting it.
  - The rejected alternative: point at crates.io and npm as a §6(d) third-party server. §6(d) keeps us obligated to ensure the source stays available, and we control neither registry's retention or deletion rules.
  - OCI images carry the `org.opencontainers.image.source` and `org.opencontainers.image.revision` labels.
- **AGPL §13 for operators.**
  - The server embeds its commit hash.
  - It exposes a configurable "source URL", which defaults to the upstream tag, through the version endpoint and a "Source" link in the web vault footer.
  - An operator who runs a modified server must point that URL at their modified source. The operator docs say so in one sentence.
- **Not an SBOM.** The notices file is not the SBOM. The SBOM (SPDX or CycloneDX) is an M8 Should (ROADMAP §4.9).

## Consequences

### Positive

- One license, one SPDX expression and one header rule across the server, core and all clients.
- **Under DCO:** contributors keep their copyright, and the owner cannot close the code. That is a trust property users can verify.
- The App Store path for the owner's own apps is settled before M7, not discovered during App Store review.
- Dependency licensing is enforced by CI today for Rust, and the same gate is required for JS before JS exists.
- AGPL §13 compliance is designed in rather than left to operators.

### Negative

- **Under DCO, relicensing becomes practically impossible** once there are outside contributors. That rules out dual licensing and a proprietary edition that uses community code.
- An app-store permission is custom legal text. It needs a paid review and is unfamiliar to license scanners.
- Some companies will not deploy AGPL software at all. That caps SMB adoption in M10, whatever the product quality.
- There is recurring release work: notices generation, source archives with vendored dependencies, and header checks. The vendored archives are large (U: size not measured).

### Risks

- **Waiting has a cost.** If the owner has not decided by the first external PR, the choice narrows. A contribution merged under DCO without the App Store permission can block App Store distribution until its author consents or the code is rewritten. **Mitigation:** do not merge external code PRs until this ADR is Accepted. Documentation PRs are fine.
- **The permission may not settle it.** A court or Apple might not treat the §7 permission as resolving the conflict (U). The fallback is that only the owner submits the iOS app, and the permission gives the owner the rights for every contributed file.
- **Copyleft leaking in.** An MPL-2.0 dependency with file-level copyleft, or a JS package with a mislabelled license, could slip through. cargo-deny checks declared metadata, not file contents. Worse, today's `allow` list admits third-party AGPL crates outright: one reachable from `rizzy-core` or any client blocks M7 App Store distribution, and CI stays green (open question 6). Review of new dependencies ([ADR 0009](0009-crypto-dependency-policy.md), [CONTRIBUTING.md](../../CONTRIBUTING.md)) is the backstop.

## Alternatives considered

- **Permissive license (MIT/Apache-2.0) for everything.** It removes every App Store and adoption problem. It also lets anyone run a closed, modified hosted fork, which contradicts ROADMAP §4.1 ("AGPL-3.0 server/core").
- **AGPL server, with `rizzy-core` under MPL-2.0 or Apache-2.0.**
  - For: it fixes the App Store problem for anyone, including forks. It lets third parties build interoperable clients on our audited core, which could help the M8 audit's reach. MPL-2.0 would still force changes to core files to be published.
  - Against: it contradicts the ROADMAP row, and it lets a competitor wrap our core in a proprietary client.
  - Rejected for now. If the owner prefers it, ROADMAP §4.1 changes first.
- **GPL-3.0 for the clients, AGPL for the server and core.** No practical difference: the AGPL core is linked into every client. It adds a second license for nothing.
- **Copyright assignment.** It gives the most control but the most friction. In practice it needs a legal entity to receive assignments, and there is none.
- **No contribution terms at all** (implicit inbound = outbound). It leaves the provenance of contributions undocumented. DCO costs one flag on `git commit`.

## Open questions for the owner

1. **"Only", "or later", or a proxy?** *Recommendation:* keep `AGPL-3.0-only`. Use the §14 proxy only if you want a path to a future version without a CLA.
2. **DCO or CLA?** This depends on question 4. *Recommendation:* DCO 1.1.
3. **Adopt the §7 App Store permission?** *Recommendation:* yes, drafted with a lawyer, committed before the first external code contribution is merged. If you pick a CLA, it becomes optional but still helps forks and packagers.
4. **M10 intent.** Will community-contributed code ever be sold under non-AGPL terms (dual license or open core)? Answer yes or no now. "Yes" means a CLA. "No" means DCO. *Recommendation:* no. Keep M10 all-AGPL. If needed, sell support and hosting, not licenses.
5. **Legal review budget.** *Recommendation:* one paid review of the README license notice, the §7 permission text and the DCO/CLA text before any App Store submission (M7). It is better done before the first external code contribution, because that is when the terms become hard to change.
6. **Remove `AGPL-3.0-only` and `AGPL-3.0-or-later` from `deny.toml` `allow`?** They do nothing for our own crates, which `[licenses.private] ignore = true` skips. Their only effect is to let third-party AGPL crates pass CI, and neither Decision 3 nor a CLA covers third-party code. *Recommendation:* yes, remove both in the PR that accepts this ADR. Admit a third-party copyleft crate (GPL, LGPL, AGPL) only through a per-crate `exceptions` entry, added by an amendment, and only if it is never reachable from an app-store client build. cargo-deny checks the whole graph and cannot tell server-only crates from client crates, so reachability is checked in review.

## References

- [`LICENSE`](../../LICENSE): AGPL-3.0 §1 (Corresponding Source), §6 (Installation Information; §6(d) source on a third-party server), §7 (additional terms), §10 (no further restrictions), §12, §13 (remote network interaction; combining with GPLv3), §14 (revised versions, proxy). V, read from the file
- [`Cargo.toml`](../../Cargo.toml) `[workspace.package]`; [`deny.toml`](../../deny.toml) `[licenses]` and `[licenses.private]`. V
- [ROADMAP.md](../ROADMAP.md) §4.1 (license policy), §4.5 (no 1Password assets), §4.9 (SBOM, managed hosting), §4.10 (mobile, M7), §4.12 (M10), §6.9 (naming)
- [ADR 0001](0001-record-architecture-decisions.md) (amendments), [ADR 0009](0009-crypto-dependency-policy.md) (dependency review), [ADR 0013](0013-shared-client-core.md) (core in every client), [ADR 0014](0014-ui-stack.md) (JS license gate), [ADR 0015](0015-desktop-tauri.md), [ADR 0016](0016-workspace-layout.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md) (sign-off, dependency rules)
- GitHub REST API, `GET /repos/lyuksovannyy/rizzy-vault` (merge and sign-off settings), 2026-09-25. V
- Developer Certificate of Origin 1.1, developercertificate.org (U: not re-read in this session)
- SPDX License List, spdx.org/licenses (U: not re-read in this session)
- VLC for iOS App Store removal, January 2011 (U)
- `cargo-about`, EmbarkStudios (U: not evaluated)
