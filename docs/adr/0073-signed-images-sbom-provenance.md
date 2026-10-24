# ADR 0073: Signed release images, SBOM and supply-chain provenance

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M8

## Context

ROADMAP §4.9 lists, as a Should: "Signed images (cosign), SBOM, provenance" (M8). [ADR 0017](0017-licensing.md) §7 already named the gap: "Not an SBOM. The notices file is not the SBOM. The SBOM (SPDX or CycloneDX) is an M8 Should (ROADMAP §4.9)." This ADR picks the format and signing mechanism ADR 0017 left open, and covers provenance, which ADR 0017 §7 did not address.

Today `.github/workflows/ci.yml` builds the multi-arch server image from `deploy/Containerfile` in the `image` job on every PR (build only, nothing pushed), and pushes it to `ghcr.io` from the `image-publish`/`image-manifest` jobs only when the repository variable `RIZZY_PUBLISH_IMAGE` is set, gated on a **push to `main`**, never a tag. The workflow's own comment calls these pushes "unsigned development builds, not a release channel" and defers "reproducible, signed images" to M8. Today those two jobs hold `contents: read` and `packages: write`; no job in `ci.yml` holds `id-token: write` (V, read from the file). `deploy/Containerfile` already pins its base images "by tag and digest", and the Rust build runs `cargo build --locked`. There is no dedicated binary-release workflow yet for `rizzy-vault`/`rv` archives.

THREAT_MODEL.md already anticipates this decision: [AST-16](../THREAT_MODEL.md#2-assets) lists "cosign identity (M8)" among release credentials; [A10](../THREAT_MODEL.md#a10-compromised-ci-or-release-credentials) says "From M8: signed images (cosign), SBOM and provenance ..., plus reproducible builds"; [§7.17](../THREAT_MODEL.md#717-distribution-channels-m1-onward) and [Q-17](../THREAT_MODEL.md#10-open-questions-for-the-owner) note that `podman auto-update` (ROADMAP §4.9, M3) follows a tag while the deploy docs pin digests, and recommend "a shipped `policy.json` template verifies them with sigstore (M8)" before auto-update is safe to enable; [AR-22](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) tracks the interim risk, "Revisit: M8 (signature verification)."

This ADR's scope is **this repository's own release artifacts**: the server container image pushed to `ghcr.io`, and the `rizzy-vault`/`rv` release binaries. [ADR 0019](0019-native-clients.md) §7 (Accepted) already ships build provenance, an SBOM and `actions/attest`-based attestations, verified with `gh attestation verify`, for a *different* artifact set — the XCFramework/AAR/nupkg/C++ tarball that native-client repositories build on, from M3, through its tag-verified, reusable release workflow. **This ADR's two new artifacts are built and signed inside that same workflow** rather than a second one (Decision §5), reusing its tag-verification, protected-environment and attestation controls as they stand. This is a new consumer of §7's workflow, not an edit to §7's text or table — ADR 0019 §7, §9.1 and §11 are unchanged (whether that still needs a formal entry in §7's own artifact table is open question 1; open question 2 covers the two signing mechanisms, cosign here and `actions/attest` there).

Cosign's keyless signing uses Sigstore's own Fulcio (short-lived certificate issuance) and Rekor (public transparency log), not a rizzy-vault protocol construction. [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) Rule 2 names a closed list of eleven constructions that are "ours" and an M8 audit target; this signs CI-produced build artifacts, not vault data, keys or protocol messages, so it is not a twelfth entry on that list, and no `alg_id` is taken from [CRYPTO.md §9.4](../CRYPTO.md#94-algorithm-registry)'s registry. **No CRYPTO.md section needs writing or changing for this ADR** (V, read from the file).

cosign, a CycloneDX generator and a CycloneDX merge tool are CI-only binaries whose own output — signatures, SBOM, provenance — is the trust artifact this ADR asks operators and client CI to verify, and the job running them gets the new `id-token: write` OIDC grant. That makes the three exactly the class [THREAT_MODEL A9](../THREAT_MODEL.md#a9-supply-chain) names in full: "Binding generators, whose output ships. One installed from git, such as uniffi-bindgen-cs, is build-time code that cargo-deny does not see." `deploy/Containerfile`'s own comment flags its current `wasm-bindgen-cli` install as an open gap, not a settled pattern — "ADR 0019 §4.1's repository-owned lockfile and approval record for it do not exist yet" — so this ADR does not copy that install method. Instead: each of the three gets an [ADR 0009](0009-crypto-dependency-policy.md)/[ADR 0019](0019-native-clients.md) §4.1-style approval record (exact pin or commit, provenance, maintainers, advisories), refreshed on every pin bump, completed and attached as part of accepting this ADR (On acceptance). None becomes a `rizzy-core`/`rizzy-sync` dependency, so ADR 0009's crypto-crate checklist proper does not apply; this is the lighter per-tool record §4.1 already requires of generators.

## Decision

### What this ADR supersedes

[ADR 0017](0017-licensing.md) §7, the **"Not an SBOM."** bullet's second sentence: "The SBOM (SPDX or CycloneDX) is an M8 Should (ROADMAP §4.9)." Replacing text:

> The SBOM is CycloneDX, not SPDX, generated per release as this ADR specifies, an M8 Should (ROADMAP §4.9).

Nothing else in ADR 0017 §7 changes: the notices file, the source offer, the OCI labels and the AGPL §13 rule all stay binding as written.

**[ADR 0019](0019-native-clients.md) §7 is not superseded, in whole or in part.** This ADR's two artifacts (Decision §5) are built and signed inside §7's existing tag-triggered release workflow, as a new consumer of it, the way a new client repository would be. §7's own text and artifact table are untouched: nothing here stops any part of it binding, so none of ADR 0020 point 9's partial-supersession machinery applies, and ADR 0019's status line does not change. Open question 1 asks the owner whether a formal entry naming these two artifacts in §7's own table is wanted anyway, for traceability.

### 1. Signing: Sigstore cosign, keyless

Release jobs sign with `cosign sign`/`sign-blob`/`attest`/`attest-blob` using GitHub Actions OIDC through Fulcio, logged in Rekor — no long-lived private key, nothing added to AST-16 beyond the already-listed "cosign identity." The new `permissions: id-token: write` goes to the one tag-triggered workflow §5 names, alongside its existing `contents: read`; it is never added to any push-triggered job in `ci.yml`, `image`/`image-publish`/`image-manifest` included.

- **Image:** `cosign sign` the per-arch manifest and the multi-arch index that ADR 0019 §7's release workflow pushes to `ghcr.io` from a tag that passed `git verify-tag` — not the output of the PR-triggered `image` job or the push-triggered, `RIZZY_PUBLISH_IMAGE`-gated `image-publish`/`image-manifest` jobs, which stay unsigned dev builds (§5).
- **Binaries:** `cosign sign-blob --yes` over each `rizzy-vault`/`rv` release archive the same workflow produces, publishing the signature bundle next to it.
- **Verification**, for operators and client CI alike — both commands name the same workflow file and the same `refs/tags/.*` ref, because both artifacts now come from the one workflow of §5:
  - Image: `cosign verify --certificate-identity-regexp '^https://github\.com/lyuksovannyy/rizzy-vault/\.github/workflows/release\.yml@refs/tags/.*$' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/lyuksovannyy/rizzy-vault:<tag>`
  - Binaries: `cosign verify-blob --bundle <archive>.sigstore --certificate-identity-regexp '^https://github\.com/lyuksovannyy/rizzy-vault/\.github/workflows/release\.yml@refs/tags/.*$' --certificate-oidc-issuer https://token.actions.githubusercontent.com <archive>`
- This does not replace ADR 0019 §7's `actions/attest`/`gh attestation verify` flow for the existing client-binding rows; the two mechanisms now sit in the same workflow, covering two different artifact families (open question 2).
- **The literal filename `release.yml` above is this ADR's own placeholder, not a name ADR 0019 §7 fixes.** §7 itself never names the workflow file; its own verification example writes `<owner>/rizzy-vault/.github/workflows/<release>.yml`, the same open placeholder. The two `cosign verify`/`cosign verify-blob` commands above must use whatever filename the implementing CI change actually gives that workflow, confirmed against ADR 0019 §7's own eventual choice (or vice versa, if this ADR's implementation lands first) — not asserted here as already settled.

### 2. SBOM: CycloneDX, per ecosystem, merged

- Rust: `cargo-cyclonedx` over the workspace `Cargo.lock`.
- JS: a CycloneDX npm generator over `pnpm-lock.yaml` for `apps/web` (exact tool: open question 3).
- Merge the two into one CycloneDX document per release with a CycloneDX merge tool (open question 3), attached to the GitHub release and to the image as a `cosign attest` predicate (`application/vnd.cyclonedx+json`).
- The SBOM's `licenses` field states each component's license id; our own crates are `AGPL-3.0-only` plus a free-text note once ADR 0017 §3's App Store additional permission text lands (its SPDX expression is still unresolved per ADR 0017 §3).

### 3. Provenance: SLSA attestation from the locked build

Predicate type `https://slsa.dev/provenance/v1`, recording the builder (workflow and run id), the source commit, the exact build invocation (`cargo build --locked --features embed-web`, the `pnpm` build), and the resolved input digests (`Cargo.lock`, `pnpm-lock.yaml`, each base-image digest from `deploy/Containerfile`). Attached via `cosign attest` (image) and `cosign attest-blob` (binaries). Target: SLSA Build Level 2 for these two rows at M8 (hosted GitHub Actions runner, signed provenance); whether they also inherit ADR 0019 §7's own Level 3 claim for its workflow is open question 4.

### 4. Operator verification: close Q-17

Ship a `containers-policy.json` template (Podman's native `containers-image` sigstore verification) pinned to the same workflow identity and OIDC issuer as §1, plus a `cosign verify` line for `docs/self-hosting.md` (not edited by this ADR). Because the signed image now comes from the tag-triggered release workflow of §5 rather than the push-triggered dev-build jobs `ci.yml` disclaims, the signature backs a build the project actually stands behind, which is what Q-17's existing recommendation is waiting on and what lets `podman auto-update` (ROADMAP §4.9) move from "ship with auto-update off" to documented-safe — once that workflow also publishes a channel tag auto-update can follow (a wiring detail, left to the CI change in §5).

### 5. Where this runs

**Decision: these two artifacts are built, signed and attested inside ADR 0019 §7's existing tag-triggered release workflow**, as a new consumer of it — not the PR-triggered `image` job or the push-triggered, `RIZZY_PUBLISH_IMAGE`-gated `image-publish`/`image-manifest` jobs in `ci.yml`. They get that workflow's `git verify-tag` gate, reusable-workflow structure, protected environment and immutable-release publishing as that workflow already defines them; this ADR adds no new workflow, identity or mechanism of its own ("What this ADR supersedes" above). The new `id-token: write` permission is scoped to that one workflow and never reaches a push-triggered job. **This is not** the second release identity/pipeline ADR 0019 §9 point 2 declined ("adds a second identity that can produce artifacts every client trusts (A10), and a second release pipeline for one maintainer. Not proposed."): that point rejects a *private embargo mirror* for security fixes; this keeps the one existing public, every-tag release path and asks it to build two more things. **This ADR does not add or edit `.github/workflows/`**; wiring these two artifacts into that workflow is a separate, owner-asked CI change (CLAUDE.md).

### Proposed invariant

**INV-100** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): Every released container image and release binary carries a cosign signature verifiable against a pinned GitHub Actions OIDC workflow identity, a CycloneDX SBOM, and a SLSA provenance attestation referencing the exact locked build inputs. | From: M8 | Verified by: a release-checklist step that runs both the §1 `cosign verify` (image) and `cosign verify-blob` (each binary archive) commands against the just-published tag, and fails the checklist on any mismatch.

### On acceptance

The PR that accepts this ADR: sets ADR 0017's status line to `Partially superseded by [ADR 0073](0073-signed-images-sbom-provenance.md) (§7 in part)`; attaches the three supply-chain approval records Context requires (cosign, the Rust and JS CycloneDX generators, the merge tool), with no acceptance without them; adds this ADR's row to [docs/adr/README.md](README.md); records the owner's answers to the open questions below in the Decision section above; and updates THREAT_MODEL's Q-17, A10, §7.17 and AR-22 text, and adds the INV-100 row to §8.9. None of these edits is made now.

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. No entry is added to ADR 0019 §7's artifact table. This ADR governs its two artifacts, and both point at the same workflow.
2. Both tools are kept: `gh attestation verify` for the binding artifacts that client CI checks, and cosign for the image and third-party Sigstore tooling.
3. The JS SBOM comes from `@cyclonedx/cyclonedx-npm`, run via `pnpm dlx`, and is merged with OWASP's `cyclonedx-cli merge`. A small `xtask` subcommand is the fallback only if the CLI cannot set a release-specific `metadata.component`.
4. The two artifacts claim SLSA Build Level 2 for M8. Level 3 is revisited together with ADR 0019 §7's own artifacts.
5. The `containers-policy.json` template ships in the same change as the signing, not in a follow-up docs PR.

Of the "On acceptance" edits, the accepting change sets ADR 0017's status line (§7 in part) and its index row. It also updates THREAT_MODEL.md Q-17, A10, §7.17 (the T row) and AR-22, and adds INV-100 to §8.9. The index row already exists. **Not attached:** the three supply-chain approval records (cosign, the Rust and JS CycloneDX generators, the merge tool). They need exact pins or commits, provenance, maintainers and advisories, which this documentation change cannot verify. "On acceptance" and Risks make them a condition of this ADR binding. Until they are attached, none of those tools may run in the release workflow. The `cosign verify` line for `docs/self-hosting.md` (§4) lands with the CI change that first signs a release, because it needs that workflow's real identity.

## Consequences

### Positive

- Once image and binary signing moves onto the tag-triggered release workflow (§5), the signed artifact is the release build, not the dev build `ci.yml` disclaims, so `podman auto-update` can be documented as safe once the policy template ships and the workflow publishes a channel tag — closing Q-17's blocker for a build the project actually stands behind.
- Answers ADR 0017 §7's deferred SBOM-format question concretely, and gives the M8 external audit (ROADMAP, "audited in M8") a supply-chain artifact to review.
- No long-lived release-signing key joins AST-16; Fulcio certificates expire in minutes.
- One tool (cosign) and one workflow cover both the image and the binaries, so operators and client CI learn one verification pattern.

### Negative

- New CI surface in an already security-critical workflow: a signing/SBOM/provenance job, a CycloneDX merge step with no first-party cross-ecosystem merge guarantee, and a new `id-token: write` permission to review.
- Two more artifact kinds now run through the one workflow ADR 0019 §11 calls the thing that "hits every client": a bug in the new image/binary build steps sits inside the same blast radius as the native-client release path.
- Keyless signing ties every release to GitHub's OIDC issuer and Sigstore's public Fulcio/Rekor uptime; an outage at release time stalls signing (the tag and build artifacts are not lost, only delayed).
- A source build (ADR 0019 §7 "Build from source") produces no signature — acceptable, since that path never relied on one.

### Risks

- A validly issued Fulcio certificate proves the workflow identity that signed, not that the workflow's own logic is trustworthy: a compromised release workflow ([A10](../THREAT_MODEL.md#a10-compromised-ci-or-release-credentials)) still produces a validly signed, malicious artifact. Signal: an attestation whose certificate identity matches but whose recorded inputs don't match a reviewed tag — the same revocation/denylist pattern as ADR 0019 §9.1.
- cosign, the CycloneDX generator(s) and the merge tool are exactly A9's "binding generators, whose output ships" class, now running inside the job that holds the new `id-token: write` grant. Unpinned or unapproved, they are a supply-chain gap in the highest-privilege job this ADR adds. Mitigated by the four approval records On acceptance requires before this ADR binds, reviewed again on every version bump, the same discipline §4.1 already applies to binding generators.
- Publishing an attestation discloses the release through Sigstore's public Rekor log the moment it is signed — the same exposure ADR 0019 §9 point 2 already accepted for client artifacts.
- CycloneDX's lead over SPDX in Rust-ecosystem tooling is a 2026 snapshot (U); revisit if that changes before M8 ships.

## Alternatives considered

- **A long-lived custodied cosign key.** Rejected: it is exactly the kind of permanent release-signing secret [AR-12](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) already flags, and it contradicts the ephemeral-credential pattern ADR 0019 §7 already set.
- **A second, independent tag-triggered workflow for just the image and binaries**, instead of building inside ADR 0019 §7's. Rejected: it duplicates the `git verify-tag`/protected-environment/attestation machinery for no benefit, and risks exactly the "second identity ... second release pipeline for one maintainer" ADR 0019 §9 point 2 already declined in the embargo-mirror context.
- **Reuse `actions/attest-build-provenance` for everything**, avoiding a second tool. Rejected as the sole mechanism: it has no native consumer in Podman's `containers-policy.json` sigstore verification, the specific M8 need behind Q-17.
- **SPDX instead of CycloneDX.** Rejected per current (U) Rust-tooling maturity: `cargo-cyclonedx` is the more active generator, and CycloneDX's merge story fits the Rust-plus-JS artifact this repository ships.
- **Ship no SBOM or provenance in M8, defer past 1.0.** Rejected: ROADMAP §4.9 and ADR 0017 §7 both already commit to M8, and it leaves Q-17 permanently blocked.

## Open questions for the owner

1. **Does joining ADR 0019 §7's workflow need a formal entry in §7's own artifact table, or is "this ADR's two artifacts run inside that workflow" enough without touching ADR 0019's text?** *Recommendation:* no edit to ADR 0019 needed. §7 governs its own table; this ADR governs these two artifacts, and both point at the same workflow by reference. Revisit only if the two tables need reconciling into one for the §14 audit-scope list.
2. **Does this ADR's cosign flow converge with ADR 0019 §7's `actions/attest` flow, now that both run from the same workflow?** *Recommendation:* keep both tools. `gh attestation verify` is what client CI already runs against binding artifacts; cosign is what `containers-policy.json` and third-party Sigstore tooling need for the image. One mechanism per consumer, not duplicated per artifact.
3. **JS CycloneDX generator and merge tool?** *Recommendation:* `@cyclonedx/cyclonedx-npm` (narrower, pnpm-lockfile-aware — justified on its own merits here, not on THREAT_MODEL A9's "as few dependencies as possible" rule, which is scoped to the browser extension's own dependency surface, not CI tooling) run via `pnpm dlx`, merged with OWASP's `cyclonedx-cli merge`; fall back to a small `xtask` subcommand only if the CLI cannot set a release-specific `metadata.component`.
4. **SLSA Build Level 2 for these two rows now, or claim the Level 3 ADR 0019 §7 already asserts for its reusable workflow ("SLSA Build Level 2, Level 3 through a reusable workflow")?** *Recommendation:* Level 2 for M8 — claim only what this ADR separately checks for the image and binaries, and revisit Level 3 for them together with revisiting it for §7's own artifacts, so the claim isn't inherited unchecked.
5. **Ship the `containers-policy.json` template in this same change, or as a follow-up docs PR?** *Recommendation:* same change — it is the one thing Q-17's existing recommendation is waiting on.

## References

- [ADR 0017](0017-licensing.md) §7 (superseded in part), §3 (App Store permission, SPDX expression unresolved)
- [ADR 0019](0019-native-clients.md) §7 (not superseded; this ADR's artifacts build inside its workflow by reference, open question 1), §9 point 2 (second-identity/second-pipeline precedent), §9.1, §11 (precedent: `actions/attest`, keyless Sigstore trust, transparency-log exposure already accepted)
- [ADR 0009](0009-crypto-dependency-policy.md) (crypto-crate scope; does not reach CI-only tools, but its approval-record pattern does, via ADR 0019 §4.1)
- [ROADMAP.md](../ROADMAP.md) §4.9 ("Signed images (cosign), SBOM, provenance", M8)
- [THREAT_MODEL.md](../THREAT_MODEL.md): AST-16, A9, A10, §7.17, §7.18, §8.9, Q-9, Q-17, AR-12, AR-22
- [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) Rule 2 (closed construction list), [§9.4](../CRYPTO.md#94-algorithm-registry) (algorithm registry, not touched) — V, read from the file
- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) `image`/`image-publish`/`image-manifest` jobs, lines ~250-321: push-to-`main`-gated, `contents: read`/`packages: write` only, no `id-token`; [`deploy/Containerfile`](../../deploy/Containerfile) (digest-pinned base images; the wasm-bindgen-cli install named as an open gap, not a model, in its own "Honest limits" comment) — V, read from the files
- cosign, a CycloneDX npm generator, cargo-cyclonedx, SLSA Build Levels, Sigstore Fulcio/Rekor: U (not independently verified in this read-only session)

<!-- All four blockers checked out against the cited sources (ci.yml, deploy/Containerfile, ADR 0014 §3, ADR 0019 §4.1/§9/§7, THREAT_MODEL A9/"How to use this document") and were applied as written; none was itself wrong. -->
