# Security policy

## Status: pre-alpha. Do not store real secrets in it.

rizzy-vault is in M0 (Foundations). There is no release, no vault code, and no security review of anything beyond the design documents. Nothing here is fit for real passwords yet. Keep using an established, externally audited password manager until rizzy-vault reaches v1.0 (end of M8). v1.0 requires an external security audit ([ROADMAP §3](docs/ROADMAP.md#3-milestones)).

## Supported versions

| Version | Supported |
|---|---|
| Any | None. Nothing has been released. |

**Proposed policy after the first release:** until v1.0, only the latest tagged release and `main` receive security fixes. The policy for v1.0 and later will be written before v1.0 ships.

## Official distribution channels

The only official source today is this repository:

<https://github.com/lyuksovannyy/rizzy-vault>

- We publish no binaries, container images, browser extensions or mobile apps.
- Anything claiming to be one is not ours. Please report it as described below.
- This list will be updated as each channel is created (container registry in M1, extension stores in M2, desktop in M3, app stores in M7).

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab and choose **Report a vulnerability**, or open <https://github.com/lyuksovannyy/rizzy-vault/security/advisories/new>.
2. Fill in the advisory form. Only the maintainers and you can see it.

If the **Report a vulnerability** button is missing, private reporting is not enabled on the repository. In that case, open a public issue titled "Security contact request" with **no details**: no component, no vulnerability class, nothing beyond the title. The maintainer then opens a draft security advisory on this repository and adds you as a collaborator on it. You send the report there; only the maintainers and you can see it.

We have no security email address, and none should be trusted unless this file lists it.

### What to include

- **What is affected:**
  - component: server role, `rizzy-core`, `rizzy-sync`, `rv`, web vault, extension, desktop, mobile, CI or release tooling, or a design document;
  - commit hash or tag;
  - relevant configuration: sync mode, database, deployment profile.
- **The attacker you assume.** Use the adversary IDs in [THREAT_MODEL.md §4](docs/THREAT_MODEL.md#4-adversaries) where you can, e.g. "A2, active malicious server".
- **Which security goal or invariant breaks,** e.g. G-5 or INV-xx from [THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Steps to reproduce,** and a proof of concept if you have one.
- **Impact:** what the attacker learns or can change.
- **Whether anyone else knows,** and whether it is public anywhere.
- **Credit:** how you want to be credited, or that you do not want credit.

A report against the design is as welcome as a report against code. Design bugs found in M0 are the cheapest ones this project will ever fix.

## What happens next

These are targets, not guarantees. The project has one maintainer.

| Step | Target |
|---|---|
| Acknowledge receipt | 7 days |
| Initial assessment: confirmed or not, severity, affected versions | 14 days |
| Fix or documented mitigation: Critical | 30 days |
| Fix or documented mitigation: High | 60 days |
| Fix or documented mitigation: Medium / Low | 90 days |

We keep you updated in the advisory thread at least every 14 days until it is closed.

**Severity** is judged against the [threat model](docs/THREAT_MODEL.md) goals:

| Severity | Examples |
|---|---|
| Critical | Vault plaintext, keys or a password-equivalent readable by the server, the network or another user (G-1, G-4), or remote code execution on a server or client. |
| High | Forged, swapped or rolled-back items or keys that the client accepts (G-2, G-3). KDF or algorithm downgrade (G-5). Key substitution without detection (G-6). Autofill into a non-matching origin (G-7). Escape from `smtp` or `icons` role containment (G-11). |
| Medium | Offline guessing that is cheaper than the design states. Share-link controls bypassed against an honest server. Metadata leaks beyond what the threat model lists. Authenticated denial of service. |
| Low | Hardening gaps with a plausible but indirect path to one of the above. |

## Disclosure

- We practice coordinated disclosure.
- **Default deadline:** we publish 90 days after the report, or when the fix is released, whichever comes first. We may agree a different date with you: later if the fix really needs it, earlier if the issue is already being exploited or already public.
- **The advisory.** Each fix is published as a GitHub Security Advisory on this repository, credited to you unless you ask otherwise. We request a CVE through GitHub for anything that affects a released version.
- **Not yet released.** Before the first release, a design flaw gets a public fix: the ADR, THREAT_MODEL.md or CRYPTO.md is changed and the change credits you. No CVE, because no affected software exists.
- **Bug bounty.** There is none. ROADMAP M8 plans one.

## Scope

**In scope:**

- All code in this repository: server roles, `rizzy-core`, `rizzy-sync`, `rv`, and later the web vault, browser extension, desktop and mobile apps.
- The design documents: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/CRYPTO.md](docs/CRYPTO.md) and the ADRs in [docs/adr/](docs/adr/). A flaw in a construction or an invariant counts even if no code implements it yet.
- Build and supply chain configuration: [`.github/workflows/`](.github/workflows/), [`deny.toml`](deny.toml), [`Cargo.lock`](Cargo.lock), and release tooling once it exists.
- Once they exist, official release artifacts from the channels listed above.

**Out of scope:**

- **Accepted limitations.** Anything listed as a non-goal ([THREAT_MODEL.md §1.4](docs/THREAT_MODEL.md#14-non-goals)) or an accepted risk ([§9](docs/THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)) is out of scope, unless you show the real impact is worse than the document states. That report is in scope. Examples of accepted limitations:
  - malware on an unlocked device;
  - a malicious server backdooring the web vault it serves;
  - the server seeing alias mail during ingress;
  - metadata visible to the server.
- **Instances run by other people.** Report those to their operator. Do not test against any instance you do not own.
- **Vulnerabilities in dependencies.** Report them upstream first. Tell us if rizzy-vault is affected, and how.
- **Low-effort reports:**
  - volumetric or network-level denial of service;
  - social engineering of maintainers or users;
  - physical attacks;
  - scanner output with no demonstrated impact;
  - missing headers or best-practice settings with no exploit path;
  - self-XSS.

## Safe harbor

We consider security research that follows this policy to be authorized and in good faith. We will not pursue or support legal action against you for it, and we will not report you to law enforcement. The conditions:

- You test only against instances and accounts you own or have explicit permission to test.
- You do not access, modify or keep other people's data. If you run into real user data, you stop, report it, and delete what you have.
- You do not degrade service for others.
- You give us reasonable time to fix the issue before disclosing it, as described above.

If in doubt, ask first through a private advisory. This statement binds the project maintainers only. We cannot speak for other instance operators, hosting providers or third parties.

## Security design

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): attackers, trust boundaries, security goals, invariants, accepted risks. [§0 "The short version"](docs/THREAT_MODEL.md#0-the-short-version) states the limits plainly.
- [docs/CRYPTO.md](docs/CRYPTO.md): primitives, key hierarchy, OPAQUE integration, KDF parameters, envelope format, flows.
- [docs/adr/](docs/adr/): the decisions behind both, with their status. All are *Proposed*; none is Accepted yet.
