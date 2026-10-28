# ADR 0106: AGPL §13 source link: `RIZZY_SOURCE_URL`, the `/api/meta` `source_url` member and the "Source" link

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1 (`rizzy-proto`, `rizzy-server`, `rizzy-wasm`/`packages/core`, web vault, `rv`, `deploy/Containerfile`, `docs/self-hosting.md`); M2 (extension options page); M3 (admin panel footer)
- Supersedes: on acceptance, in part: [ADR 0028](0028-api-v1-http-conventions.md) item 14 (its first sentence, the `/api/meta` shape); [ADR 0048](0048-per-account-storage-quota.md) §1 (its last sentence, the settings list, which is the binding text of ADR 0028 item 12's settings clause). §7 gives both parts word for word and their replacements. It implements [ADR 0017](0017-licensing.md) §7 "AGPL §13 for operators" and supersedes nothing in ADR 0017.

## Context

**Trigger.** The 2026-10-25 ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)) lists it as **M9**: "**AGPL §13 source URL** (version-endpoint field, web footer). ADR 0028's closed lists leave no room for it." (raw finding **G02-5** [major], [docs/reviews/2026-10-25-raw/G02.md](../reviews/2026-10-25-raw/G02.md)). The owner said "start" on 2026-10-25, after the review.

**What is Accepted.** [ADR 0017](0017-licensing.md) §7 "AGPL §13 for operators" (V, lines 194–197):

> - The server embeds its commit hash.
> - It exposes a configurable "source URL", which defaults to the upstream tag, through the version endpoint and a "Source" link in the web vault footer.
> - An operator who runs a modified server must point that URL at their modified source. The operator docs say so in one sentence.

ADR 0017 §7 also says each release "links to its exact tag and attaches a complete source archive: the tagged tree plus the source of every dependency compiled into the release artifacts", because "a tag archive does not contain the crates statically linked into our binaries" and ADR 0017 reads AGPL §1 as including them (V, lines 190–191).

**Why nothing can be built.** Two Accepted closed lists have no place for the URL (G02-5, V):

- [ADR 0028](0028-api-v1-http-conventions.md) item 12 names every server setting and refuses "unknown, repeated or malformed lines". Its settings clause is now [ADR 0048](0048-per-account-storage-quota.md) §1's last sentence (ADR 0048's own table: "Item 12, settings clause … | §1"), which ends at `RIZZY_ACCOUNT_QUOTA_BYTES`. No `RIZZY_SOURCE_URL`.
- ADR 0028 item 14 fixes the `/api/meta` body: "`{"server_version":"x.y.z","api_versions":["v1"],"min_client_versions":[{"platform","version"}]}`". No source member.

The code follows them (V, read 2026-10-25 in this worktree): `crates/rizzy-proto/src/meta.rs` `MetaResponse` has exactly `server_version`, `api_versions`, `min_client_versions`; `crates/rizzy-server/src/config.rs` has no source setting; the server has no `build.rs` and embeds no commit; the web vault has no footer; `docs/self-hosting.md` says nothing about AGPL §13; `deploy/Containerfile` sets no `org.opencontainers.image.revision` label. G02-5: "An operator running a modified server therefore has no compliant way to point users at their source … and the M1 server already ships as a container image." G02-5's suggested resolution, which this ADR follows with changes: "a `RIZZY_SOURCE_URL` setting (default: the upstream tag URL derived from the embedded commit), a `source_url` and `commit` member in `/api/meta`, the web-vault footer link, and the one-sentence operator note in docs/self-hosting.md; state size/scheme limits (https only, ≤ 2 KiB) and that clients render it through `SafeLink` (INV-42)."

**Facts used.**

- The workspace `Cargo.toml` has `repository = "https://github.com/lyuksovannyy/rizzy-vault"` and `version = "0.0.0"` (V). Cargo exposes them to the compiling crate as `CARGO_PKG_REPOSITORY` and `CARGO_PKG_VERSION` (L, Cargo reference, not re-read for this ADR).
- No release tags exist yet (`git tag` is empty, V); no ADR fixes the tag name. ADR 0073 publishes development images on a push to `main`, "never a tag" (V). So today every image is untagged.
- GitHub serves a tree at `<repo>/tree/<ref>` and a release page at `<repo>/releases/tag/<tag>` (L, common knowledge, not checked against GitHub documentation).
- AGPL-3.0 §13 begins "if you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network … an opportunity to receive the Corresponding Source of your version … from a network server at no charge" (L, quoted from memory of the licence text, not re-read for this ADR). Every legal reading below is marked U: none is legal advice and none was checked by a lawyer.
- The web vault's only link component is `SafeLink` (`apps/web/src/SafeLink.tsx`, INV-42): `http:`/`https:` only, `target="_blank" rel="noopener noreferrer"` (V). `packages/core` already fetches `/api/meta` in `checkServer` before anything secret is typed (V).

**Other ADRs that change the same sentence.** Two Proposed ADRs also supersede ADR 0048 §1's settings sentence (or the ADR 0028 clause it replaced): [ADR 0087](0087-invite-only-signup-tokens.md) §10.1 adds `RIZZY_SIGNUP` value `invite` (and, under its open question 2, ", default `invite`"), and says "whichever of the two is accepted later restates the other's change in its replacement"; [ADR 0066](0066-share-email-otp-verification.md) "What this ADR supersedes" adds `RIZZY_SMTP_URL` and `RIZZY_SMTP_FROM`, quoting ADR 0028's older text (without `RIZZY_ACCOUNT_QUOTA_BYTES`). §7.2 restates both. [ADR 0086](0086-instance-settings-persistence.md) (Proposed) moves some settings into the database; the source URL is not one of them (§1). No other ADR in 0001–0099 changes `/api/meta`'s members (grep of `docs/adr` for `api/meta` and `item 14`, V).

## Decision

### 1. The setting `RIZZY_SOURCE_URL`

- **Where it comes from.** The environment or the `NAME=value` configuration file, environment over file, like every ADR 0028 item 12 setting. It is not a flag (`--roles` and `--config` stay the only flags), not an instance setting in the database (ADR 0086 does not list it, and this ADR does not add it), and not editable in the admin panel. It is read once at startup; changing it takes a restart.
- **Not a secret.** It holds a public URL. It may appear in logs: the server logs it once at `info` at startup ("source URL: <value>") so the operator sees what users are shown. It stays out of the zeroizing secret path of ADR 0028 item 12's secret boundary.
- **Grammar** (one type, `rizzy_proto::meta::SourceUrl`, used by the server's configuration parser and by every client parser; §3). A value is valid if and only if all hold:
  1. Length 9 to **2048 bytes** inclusive (`SourceUrl::MAX_LEN = 2048`).
  2. Every byte is printable ASCII `0x21`–`0x7E`. No space, no control character, no non-ASCII byte: an internationalised host is written as its `xn--` form and any other non-ASCII text percent-encoded.
  3. It begins with exactly `https://` (lowercase). `http://`, `HTTPS://`, any other scheme and scheme-relative `//…` are invalid. There is no exception for `localhost`.
  4. The authority (the bytes after `https://` up to the first `/`, `?`, `#` or the end) is `host` or `host:port`: `host` is 1–253 bytes of `[A-Za-z0-9.-]`, neither starting nor ending with `.` or `-`; `port` is 1–5 ASCII digits with value 1–65535. A `@` in the authority (userinfo) is invalid, so a URL cannot carry a password or hide its real host behind `user@`. A bracketed IP literal (`[::1]`) is invalid; a dotted IPv4 host is allowed because it fits the host rule.
  5. The rest (path, query, fragment, possibly empty) uses only RFC 3986's unreserved and reserved characters and `%`: `A-Z a-z 0-9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; = %`, and every `%` is followed by two hex digits. (RFC 3986 character sets: L, from memory.)
  6. No normalisation: the value is stored and sent byte for byte as configured, so what the operator wrote is what users get.
- **Empty value.** `RIZZY_SOURCE_URL=` (set but empty) is invalid, not "unset". To use the default, leave the setting out. *Why:* ADR 0028 item 12's "a typo must fail, not pass"; an empty value is most often a compose variable that was meant to be filled in.
- **Error.** An invalid value stops startup with `ConfigError::Invalid("RIZZY_SOURCE_URL")`, the same error, message form and exit as every other invalid setting in `config.rs` (the message names the setting; it does not quote the value, for uniformity with the other settings, although the value is not secret). A repeated line is refused as today. There is no partial start and no fallback to the default.
- **Unset.** The default of §2 applies.

### 2. The default: this build's upstream source

The default is a compile-time constant of the `rizzy-server` binary, computed by a pure function `default_source_url(repository, version, build_tag, build_commit) -> SourceUrl` in `rizzy-server` from four compile-time inputs. No `build.rs`, no `git` call and no I/O at build or run time: the inputs come from `env!`/`option_env!`.

| Input | Source | Valid when |
|---|---|---|
| `repository` | `CARGO_PKG_REPOSITORY` (workspace `repository`) | it satisfies §1's grammar, has no query or fragment and does not end in `/`; `cargo xtask` checks this (implementation step 4), so an invalid value fails CI, not the server |
| `version` | `CARGO_PKG_VERSION` | always (Cargo enforces SemVer, L) |
| `build_tag` | `option_env!("RIZZY_BUILD_TAG")` | present and exactly `"v"` + `version` |
| `build_commit` | `option_env!("RIZZY_BUILD_COMMIT")` | present and exactly 40 or 64 lowercase hex digits (a SHA-1 or SHA-256 Git object id) |

Rules, first match wins:

1. `build_tag` valid → `<repository>/releases/tag/<build_tag>`. The release page is where ADR 0017 §7 attaches the complete source archive (tagged tree plus vendored dependency sources), so this is the most complete answer to "the upstream tag".
2. else `build_commit` valid → `<repository>/tree/<build_commit>`. This covers ADR 0073's untagged `main` images, which have no tag to point at.
3. else → `<repository>`, and the server logs one `warn` at startup: "this build has no exact source reference; set RIZZY_SOURCE_URL". A present but invalid `RIZZY_BUILD_TAG` or `RIZZY_BUILD_COMMIT` is ignored for the rule (the next rule applies) and named in that warning; it never stops the server. The warning is not logged when `RIZZY_SOURCE_URL` is set.

For the upstream repository today: a `main` image built from commit `c` defaults to `https://github.com/lyuksovannyy/rizzy-vault/tree/c`; a future release `1.0.0` built with `RIZZY_BUILD_TAG=v1.0.0` defaults to `https://github.com/lyuksovannyy/rizzy-vault/releases/tag/v1.0.0`. Both URL forms are L (§Context).

**Tag name.** This ADR fixes release tags as `v<version>` (`v1.0.0`) for the purpose of rule 1. No ADR names tags yet; a later release ADR may supersede this point.

**"The server embeds its commit hash"** (ADR 0017 §7) is realised by `RIZZY_BUILD_COMMIT`: `deploy/Containerfile` gains `ARG RIZZY_BUILD_COMMIT` and `ARG RIZZY_BUILD_TAG` (empty by default; an empty variable counts as absent), exported to the server's `cargo build`; CI passes `${{ github.sha }}` (L: GitHub Actions context, not re-read) for `RIZZY_BUILD_COMMIT`, and the release job, when one exists, also passes the tag. The same value fills the `org.opencontainers.image.revision` label that ADR 0017 §7 already requires. A build from a source archive without these variables gets rule 3. The commit is exposed only through the default URL and the startup log; `/api/meta` gets no separate `commit` member (open question 1).

### 3. `/api/meta` gains `source_url`

- **Member.** `"source_url"`: a JSON string, **always present** in every `GET /api/meta` answer of a server that implements this ADR. Its value is the parsed `RIZZY_SOURCE_URL`, or §2's default when unset, so it always satisfies §1's grammar (the server's `MetaResponse` field has type `SourceUrl`; an invalid value cannot be serialised). It is unauthenticated and public like the rest of `/api/meta`: it holds no secret and nothing about any account.
- **Shape** (replacing item 14's first sentence, §7.1): `{"server_version":"x.y.z","api_versions":["v1"],"min_client_versions":[{"platform","version"}],"source_url":"https://…"}`. Member order is not meaningful.
- **Client parsing is lenient for this member only.** Clients parse `source_url` with `SourceUrl::parse`. Absent (an older server), not a string, or not matching §1 (for example over 2048 bytes, or `http:`) → the client treats it as absent: it shows no source link (§4) and parses the rest of `/api/meta` normally. It is never an error, never `invalid_request`, never blocks login. *Why:* `/api/meta` is checked before anything secret is typed; a bad source link must not lock users out, and the client cannot fix the operator's configuration.
- **Versioning.** Purely additive: ADR 0028 item 14 already says "unknown members ignored by clients", so older clients ignore it; newer clients treat its absence as above. No `api_versions` change, no minimum-client-version change, no new error code, no migration and no persistent format: no client stores the value (§4).
- **Wire type in `rizzy-proto`.** `MetaResponse` gains `source_url: Option<SourceUrl>` with `#[serde(default, deserialize_with = …)]` mapping any invalid value to `None`; the server always sets `Some`. `SourceUrl` deserialises from a JSON string through `SourceUrl::parse`, bounded by `MAX_LEN` before any scan, and never panics (fuzzed, implementation step 1).

### 4. Where users see it

Every client renders the link only from a value that passed `SourceUrl::parse`, so only `https:`. The link always opens outside the vault: a new tab or the system browser, with no opener and no referrer. No client stores the value: it lives in memory for the session, so it adds nothing to the local cache format ([ADR 0026](0026-client-device-state-and-cache.md)) or extension storage.

| Client | Where | Text | Behaviour |
|---|---|---|---|
| Web vault (M1) | A footer on every screen, including signup, login and unlock (users interact with the server before they log in) | "Source" | `<a href=… target="_blank" rel="noopener noreferrer" title="<the URL>">`; the URL comes from `checkServer`'s answer, which `packages/core` extends to return `{ serverVersion, sourceUrl?: string }`. No link (and no placeholder text) until `/api/meta` has answered, or when `sourceUrl` is absent; the screen's existing server error covers a failed fetch. The component also checks the `https:` prefix itself (defence in depth: the function `SafeLink` uses, plus an `https:`-only check) |
| Extension (M2) | Options page, an "About this server" line, shown once a server origin is configured | "Server source code: " + the full URL as the link text | Fetched with `/api/meta` when the options page opens; not in the popup or the inline menu |
| `rv` (M1) | `rv account status` output | `server source: <url>` | One unauthenticated `GET /api/meta` if the command does not already make one; if it fails or the member is absent, prints `server source: unavailable` and the command's output and exit status are otherwise unchanged |
| Admin panel (M3, [ADR 0060](0060-admin-panel-stack-boundary.md)) | Page footer | "Source" | Rendered by the server from the same parsed value |
| Native apps (M3+, [ADR 0019](0019-native-clients.md)) | About screen | "Server source code: " + URL | Required when those apps are built; their own licence notices are ADR 0019 §15's matter, not this ADR's |

The client's own source (the extension package, `rv`, native apps) is a conveyance matter under ADR 0017 §7's source offer and ADR 0019 §15 (review G02-6), not this link: this link names the source of **the server and the web vault it serves**.

### 5. What operators must do

- **Running an unmodified upstream build** (an upstream image, or a build of an unmodified upstream tag or commit with the build variables set): nothing. The default already points at the upstream source. Whether AGPL §13 applies at all to an unmodified copy: L, §13 is worded "if you modify the Program"; the link is shown anyway.
- **Running a modified build:** set `RIZZY_SOURCE_URL` to an `https://` address where every user of the server can get, at no charge and without signing up, the complete source of the exact version that runs, including the web vault. The operator docs say this in one sentence (ADR 0017 §7):

  > If you run a modified rizzy-vault server or web vault, set `RIZZY_SOURCE_URL` to an https address where everyone who uses your server can download, free of charge and without an account, the complete source code of exactly the version you run.

  followed by a short plain explanation in `docs/self-hosting.md`:
  - "Modified" means any change to the code you build: a patch, a fork, a changed dependency version, a rebuilt web vault with your changes. Changing only settings (the `RIZZY_*` values) or the deployment around the server (reverse proxy, compose file) is not a change to the code (U: our reading, not legal advice).
  - Point the URL at the exact version, not at a branch that moves: a tag, a commit, or a release page.
  - Upstream releases attach an archive with the source of every dependency compiled in (ADR 0017 §7). If you modify the code, publish the same kind of archive for your build, or link to a page that has it. Whether a link to a repository tree alone is enough: U; the project reads AGPL §1 as including the dependency sources (ADR 0017 §7), so the safe course is the archive.
  - A link that needs a login (for example a private repository) does not meet "at no charge" for users who have no account there (U).
  - The default for a build from a fork still points at upstream (it comes from the workspace `repository` field and your commit, which upstream may not have). Set the URL; the server cannot tell that your build is modified.
- **Legal readings, all U:** that §13 is triggered by modification and remote interaction; that the web vault's JavaScript is also conveyed to the browser and so falls under AGPL §6 as well as §13; that a footer link plus the `/api/meta` member meets "prominently offer". The project states its reading; it does not certify any operator's compliance.

### 6. Limits, errors, crash and retry

- Limits: 2048 bytes for the setting and the member (§1); the existing 64 KiB configuration file limit and `/api/meta`'s existing response limits are unchanged.
- Errors: one configuration error (§1). No new HTTP status or `{"error":…}` code.
- Crash and retry: nothing is written. The value is parsed at startup and immutable for the process; a crash or restart re-parses it. Clients that fail to fetch `/api/meta` retry as they already do and show no link meanwhile.

### 7. What this ADR supersedes

Two Accepted sentences ([ADR 0020](0020-partial-supersession.md) point 9). Nothing else in ADR 0028, ADR 0048 or ADR 0017 changes.

#### 7.1 ADR 0028 item 14, first sentence

Word for word:

> **`GET /api/meta`.** `{"server_version":"x.y.z","api_versions":["v1"],"min_client_versions":[{"platform","version"}]}`, unauthenticated, unknown members ignored by clients.

Replacement, in full:

> **`GET /api/meta`.** `{"server_version":"x.y.z","api_versions":["v1"],"min_client_versions":[{"platform","version"}],"source_url":"https://…"}`, unauthenticated, unknown members ignored by clients. `source_url` is always present: the `RIZZY_SOURCE_URL` setting, or this build's upstream source when it is unset, an `https://` URL of at most 2048 bytes where users get the source of the running server and web vault ([ADR 0017](0017-licensing.md) §7, AGPL §13); a client that finds it absent or invalid shows no source link and otherwise uses the answer normally ([ADR 0106](0106-agpl-source-url.md) §1–§3).

Item 14's later sentences ("It is public on purpose: …", the **Amended** passage on `Rizzy-Client`, the *Why*) stay binding and unchanged.

#### 7.2 ADR 0048 §1, last sentence (the binding text of ADR 0028 item 12's settings clause)

Word for word:

> Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

Replacement, in full, if neither ADR 0087 nor ADR 0066 is Accepted when this ADR is:

> Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`, `RIZZY_SOURCE_URL` (default: this build's upstream source, [ADR 0106](0106-agpl-source-url.md) §1–§2).

**Coordination with ADRs 0087 and 0066 (both Proposed).** Whichever of the three is accepted later restates the earlier ones' additions, as ADR 0087 §10.1 already says for itself and ADR 0066. If either is Accepted before this ADR, this ADR's replacement is the sentence above with that ADR's addition made, exactly:

- ADR 0087 Accepted earlier: `RIZZY_SIGNUP` (`closed`|`open`) becomes `RIZZY_SIGNUP` (`closed`|`invite`|`open`), or `RIZZY_SIGNUP` (`closed`|`invite`|`open`, default `invite`) if the owner accepted ADR 0087's open question 2.
- ADR 0066 Accepted earlier: `RIZZY_SMTP_URL`, `RIZZY_SMTP_FROM` are inserted after `RIZZY_ACCOUNT_QUOTA_BYTES`. (ADR 0066 quotes ADR 0028's older clause, without `RIZZY_ACCOUNT_QUOTA_BYTES`; ADR 0048's setting stays. List order carries no meaning.)

With both earlier (and ADR 0087's open question 2 answered "no"), the replacement is, in full:

> Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`invite`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`, `RIZZY_SMTP_URL`, `RIZZY_SMTP_FROM`, `RIZZY_SOURCE_URL` (default: this build's upstream source, [ADR 0106](0106-agpl-source-url.md) §1–§2).

If this ADR is Accepted first, ADR 0087's and ADR 0066's replacements, when accepted, keep "`RIZZY_SOURCE_URL` (default: this build's upstream source, [ADR 0106](0106-agpl-source-url.md) §1–§2)" at the end of the list. ADR 0066's secret-boundary passage is not touched by this ADR: `RIZZY_SOURCE_URL` holds no secret.

ADR 0048 §1's other sentences (the quota setting) and ADR 0028 item 12's other clauses ("; from the environment or a `NAME=value` file …", the secret boundary, the *Why*) stay binding.

### 8. What this ADR does not decide

- ADR 0002 point 3's list of what `/api/meta` returns is not superseded: that list says what the endpoint carries, and adding a member is additive under ADR 0028 item 14's "unknown members ignored" (open question 3 offers a formal replacement if the owner prefers).
- The client-side licence notices and source offers of ADR 0019 §15 (review G02-6), the SBOM (ADR 0073), and a release workflow.
- No THREAT_MODEL invariant: the link is ordinary public metadata; its rendering rules (https only, no opener, no referrer) are INV-42's existing rule for links, narrowed to `https:`. If the owner wants one, its number is next free at acceptance.

## Consequences

**Positive.**

- An operator of a modified server has one documented, validated place to point users at the source, as ADR 0017 §7 promised; upstream operators get a correct default with no action.
- `main` images point at their exact commit, not a moving branch.
- Additive on the wire; no migration, no persistent format, no new error code; older clients are unaffected.

**Negative and trade-offs.**

- `/api/meta` now discloses the build's commit (for untagged builds) or tag. `server_version` is already public, so this adds little for an attacker who wants to match a version to known bugs (judgement, U). A modified build's URL may reveal the operator's fork; that is the point of §13.
- A malicious operator can set any https URL, including a phishing page. The operator already serves the web vault's code, so this adds no power over the vault; clients open the link outside the vault, with no opener and no referrer, and the extension and `rv` show the full URL. The web footer shows only "Source" (with the URL as its tooltip), a usability choice over showing the whole URL.
- The default for a fork's build is wrong (upstream repository, fork's commit). The server cannot detect a modification; the docs carry this duty (§5).
- Strict grammar: some valid URLs (IP literals, uppercase scheme, raw Unicode) are refused. Operators can always write the ASCII form.
- An empty `RIZZY_SOURCE_URL=` fails startup; a compose file that passes an unset variable through will stop the server until the line is removed.
- `rv account status` may gain one unauthenticated request.

**Rejected alternatives.**

- *`http:` allowed.* A plain-HTTP link can be rewritten on path; a public source host has no reason to need it.
- *Validate with the `url` crate.* A new dependency for a narrow, fixed grammar; the hand-written parser is small, bounded and fuzzed. (It is not cryptography, so the "no home-made crypto" rule does not apply.)
- *Default `<repository>` always.* Not "the exact version" ADR 0017 §7 asks for.
- *Default derived by running `git` in a `build.rs`.* Fails for builds from a source archive, adds a build script, and makes builds depend on the checkout state; CI already knows the commit.
- *A `commit` member in `/api/meta`* (G02-5's suggestion): open question 1.
- *An instance setting editable in the admin panel* (ADR 0086 style): the source of the running binary changes only with a new deployment, which already restarts the server.
- *Client hard-fails on an invalid `source_url`*: locks users out over a cosmetic, operator-side misconfiguration that the server's own validation already prevents.

## On acceptance

Not made now; each is the owner's act or follows it.

1. ADR 0028's status line gains "; [ADR 0106](0106-agpl-source-url.md) (item 14 in part)", appended after any earlier entry.
2. ADR 0048's status becomes "Partially superseded by [ADR 0106](0106-agpl-source-url.md) (§1 in part: its settings sentence)", or gains that entry after ADR 0087's or ADR 0066's if one of them was accepted first. The owner records which §7.2 variant applies.
3. ADR 0017's status is unchanged (this ADR implements §7 and supersedes none of it), unless open question 2 is answered yes.
4. CLAUDE.md's Accepted list and the README index row are updated by the lead.
5. `docs/HANDOFF.md` names the implementation as open work; `docs/self-hosting.md` gets its row and section with the implementation (not before, so the docs do not describe a setting that does not exist yet).
6. If `docs/reviews/2026-10-25-errata-candidates.md` lists G02-5/M9, it is marked as addressed by this ADR.

## Implementation plan

Once Accepted, in this order; each step a Conventional Commit. No database migration is needed.

1. **`rizzy-proto`: `SourceUrl`.** `meta.rs`: `SourceUrl` newtype, `MAX_LEN = 2048`, `parse(&str) -> Result<SourceUrl, SourceUrlError>` implementing §1 rules 1–5 (length check before scanning), `Serialize`/`Deserialize`; `MetaResponse.source_url: Option<SourceUrl>` with the lenient deserialiser of §3. Tests: a table of valid values (the two upstream defaults, a port, a query and fragment, `%2F`, exactly 2048 bytes) and invalid ones (empty, 8 and 2049 bytes, `http://`, `HTTPS://`, `//host`, space, tab, `é`, `user@host`, `user:pw@host`, `[::1]`, `host:0`, `host:65536`, `host:123456`, `-host`, `host.`, `%zz`, `%4`, `"`, `<`, `\`); `MetaResponse` round trip with the member, without it (`None`), with a non-string and with an invalid string (`None`, other members intact), and with an unknown extra member (ignored). Fuzz: extend an existing `/api/meta` fuzz target if there is one, else add a `source_url` target (parse never panics; a parsed value re-serialises byte for byte). Must build for wasm (`cargo check-wasm`).
2. **`rizzy-server`: setting and default.** `config.rs`: `SOURCE_URL` constant, parse into `Config.source_url: Option<SourceUrl>`, `ConfigError::Invalid(SOURCE_URL)`; pure `default_source_url` (§2) with unit tests for all three rules, an invalid tag (`1.0.0`; `v1.0.1` against version `1.0.0`), an invalid commit (39 hex, uppercase hex, 41 hex), and a 64-hex commit. Config tests: environment, file, environment over file, empty refused, invalid refused with an error that names only the setting, a repeated file line refused. Startup `info` log of the URL and the rule-3 `warn` (log-capture test).
3. **`rizzy-server`: `/api/meta`.** `http/api.rs` fills `source_url`. Integration tests: unset → the compiled default; set → byte for byte the configured value; the member is present on every answer, with and without `Rizzy-Client`.
4. **`xtask`.** A check that the workspace `repository` satisfies §2's row (in an existing xtask check or a new one; wiring a new one into CI is the owner's call, since `.github/workflows/` is not edited unless asked).
5. **Build.** `deploy/Containerfile`: `ARG RIZZY_BUILD_COMMIT`, `ARG RIZZY_BUILD_TAG`, passed to `cargo build`; the `org.opencontainers.image.revision` and `org.opencontainers.image.source` labels (ADR 0017 §7). The CI change that passes the commit is the owner's to approve. Manual check: a built image's `/api/meta` shows `…/tree/<sha>`.
6. **`rizzy-wasm` / `packages/core`.** `checkServer` returns `{ serverVersion, sourceUrl?: string }`; unit tests with and without the member.
7. **Web vault.** A footer component on every screen; unit tests: link present with `target="_blank"`, `rel="noopener noreferrer"`, `title`; absent without `sourceUrl`; absent for a non-`https:` value even if one reached it. e2e: the login screen of a server started with `RIZZY_SOURCE_URL=https://example.com/src` shows "Source" linking there.
8. **`rv`.** `rv account status` prints `server source: <url>` or `server source: unavailable`; tests for both against a stub server.
9. **Docs.** `docs/self-hosting.md`: the settings-table row (`RIZZY_SOURCE_URL` | this build's upstream source | an `https://` URL, at most 2048 bytes) and the §5 section with its one sentence; `HANDOFF.md` updated.
10. **M2: extension options page; M3: admin panel footer**, each with a rendering test and, for the extension, a test that nothing is written to extension storage.

## Open questions for the owner

1. **A separate `commit` member in `/api/meta`** (G02-5 suggested one)? Recommendation: **no** for now. `source_url` already carries the commit for untagged builds and the tag for releases, which is what §13 needs; a second member is one more public build identifier with no client that uses it. A later ADR can add it additively.
2. **Is ADR 0017 §7's "defaults to the upstream tag" met by §2** (the release page of the tag for tagged builds; the tree at the commit for untagged `main` images, which have no tag), or do you want a formal partial supersession of that sentence? Recommendation: **no supersession**; §2 is the tag default wherever a tag exists and covers a case §7 did not foresee. If you prefer the formal route, the replacement for ADR 0017 §7's second bullet, in full: "It exposes a configurable "source URL", which defaults to this build's upstream source (the release page of its tag, or the tree at its commit for an untagged build, [ADR 0106](0106-agpl-source-url.md) §2), through the version endpoint and a "Source" link in the web vault footer."
3. **Also replace ADR 0002 point 3's `/api/meta` list** so it names the source URL? Recommendation: **yes, if you want no doubt**, though §8 argues it is additive. Replacement for the list as ADR 0022 left it, in full: "It returns: the server version and the API versions it serves; the minimum client version per platform; the URL of the running server's source code ([ADR 0106](0106-agpl-source-url.md))." If yes, the Supersedes line and On acceptance item 1 gain ADR 0002 point 3 (the `/api/meta` list) in part.
4. **ROADMAP.** No ROADMAP row names the source link; the nearest is the M0 row "License policy: AGPL-3.0 server/core; decide client license; dependency license allow-list". Recommendation: add an M1 row "AGPL §13 source link (ADR 0106)", because the M1 server already ships as an image.
