<!--
Use this template for a PR that edits data/equivalence/groups.txt (ADR 0038 §4).
GitHub does not show a chooser for pull-request templates the way it does for issues. To get
this one, add "?template=equivalence-list.md" to the branch-compare URL before you open the
PR (e.g. .../compare/main...your-branch?quick_pull=1&template=equivalence-list.md), or open
the PR normally and paste this file's contents into the description yourself.

Read ADR 0038, section "4. Review rules for list entries", and docs/equivalence-list.md,
section "2. Editing the source file", first.
-->

## What this changes

- [ ] Links the proposal issue (opened from the `equivalence-group` issue template): #
- [ ] States which group(s) in `data/equivalence/groups.txt` are added or changed, and the
      domains involved.

## ADR 0038 §4 review rules

- [ ] **Ownership proof** is linked for every domain added, in the issue or in this PR
      description (point 1). "Looks plausible next to a known brand" is not proof.
- [ ] **Per-ccTLD-variant proof.** Each ccTLD pairing (e.g. `brand.com` / `brand.co.uk`) has
      its own evidence, not an assumption from the base domain (point 4).
- [ ] **No third-party-hostable domain**, unless the Public Suffix List already splits that
      suffix by registrant — if so, `third_party_hostable = 1` is set in
      `data/equivalence/groups.txt` and the PSL entry is cited here (point 3).
- [ ] **Two-maintainer review.** Until a second maintainer exists, this box confirms the
      owner's own review is recorded here with the evidence cited, for a later second
      reviewer to audit (point 2).
- [ ] **A next scheduled re-check** is noted here (at minimum the next release cycle) (point
      5).
- [ ] The group stays within the "small list, high bar" rule: a well-known multi-domain brand
      with clear public ownership evidence (point 6).

## Format

- [ ] The new or changed line(s) in `data/equivalence/groups.txt` follow the file's own
      header format, domains sorted bytewise within the group, no duplicates.
- [ ] A new group's `group_id` is freshly random (not derived from the domains); an existing
      group's `group_id` is unchanged.

## Out of scope for this PR

Compiling and signing a new `data/equivalence/list.bin`, and updating
`crates/rizzy-match/src/compiled.rs`, are a separate, owner-only step
(docs/equivalence-list.md §§3–4; ADR 0038 §3) that happens after this PR is reviewed and
merged. This PR only changes the human-editable source and its review record.
