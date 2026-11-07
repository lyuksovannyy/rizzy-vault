// SPDX-License-Identifier: AGPL-3.0-only

//! The source URL `/api/meta` serves ([ADR 0106] §1–§2; [ADR 0017] §7, AGPL §13).
//!
//! The `RIZZY_SOURCE_URL` setting ([`crate::config`]) wins. When it is unset, the default is
//! this build's upstream source, computed by the pure [`default_source_url`] from four
//! compile-time inputs ([`compiled_default`]): the workspace `repository` and `version`, and
//! the optional build variables `RIZZY_BUILD_TAG` and `RIZZY_BUILD_COMMIT` that
//! `deploy/Containerfile` passes to `cargo build` (an empty variable counts as absent). No
//! `build.rs`, no `git` call and no I/O. First match wins:
//!
//! 1. a valid tag (exactly `v` + the version) → `<repository>/releases/tag/<tag>`;
//! 2. else a valid commit (40 or 64 lowercase hex digits) → `<repository>/tree/<commit>`;
//! 3. else `<repository>`, and startup logs one `warn` naming any build variable it ignored.
//!
//! [`served`] picks the URL and logs it once at `info` (it is public, ADR 0106 §1). A build
//! whose `repository` field is not a valid base (`cargo xtask check-deps` checks upstream's)
//! has no default; such a server refuses to start unless `RIZZY_SOURCE_URL` is set, so
//! `/api/meta` always carries a valid `source_url` (§3).
//!
//! [ADR 0017]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0017-licensing.md
//! [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md

use rizzy_domain_auth::types::SourceUrl;

use crate::log::{self, Field};

/// The rule of [ADR 0106] §2 that gave a default.
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultRule {
    /// Rule 1: the release page of the build's tag.
    Tag,
    /// Rule 2: the tree at the build's commit.
    Commit,
    /// Rule 3: the repository alone; the build has no exact source reference.
    Repository,
}

/// The compiled default source URL and how it was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultSourceUrl {
    /// The URL.
    pub url: SourceUrl,
    /// The rule that gave it.
    pub rule: DefaultRule,
    /// `RIZZY_BUILD_TAG` was present but not `v` + the version.
    pub ignored_tag: bool,
    /// `RIZZY_BUILD_COMMIT` was present but not 40 or 64 lowercase hex digits.
    pub ignored_commit: bool,
}

/// The rule-3 warning's advice ([ADR 0106] §2).
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
const INEXACT_ADVICE: &str = "this build has no exact source reference; set RIZZY_SOURCE_URL";

/// Whether `commit` is a Git object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
fn is_commit(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64)
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// [ADR 0106] §2's default from its four inputs; `None` when `repository` is not a valid
/// base (a [`SourceUrl`] with no query or fragment and no trailing `/`). An empty tag or
/// commit counts as absent; a present but invalid one is ignored and reported.
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
#[must_use]
pub fn default_source_url(
    repository: &str,
    version: &str,
    build_tag: Option<&str>,
    build_commit: Option<&str>,
) -> Option<DefaultSourceUrl> {
    let base = SourceUrl::parse(repository)
        .ok()
        .filter(SourceUrl::is_base)?;
    let tag = build_tag.filter(|t| !t.is_empty());
    let commit = build_commit.filter(|c| !c.is_empty());
    let valid_tag = tag.filter(|t| t.strip_prefix('v') == Some(version));
    let valid_commit = commit.filter(|c| is_commit(c));
    let under = |path: &str, reference: &str| {
        SourceUrl::parse(&format!("{}/{path}/{reference}", base.as_str())).ok()
    };
    let (url, rule) = if let Some(url) = valid_tag.and_then(|t| under("releases/tag", t)) {
        (url, DefaultRule::Tag)
    } else if let Some(url) = valid_commit.and_then(|c| under("tree", c)) {
        (url, DefaultRule::Commit)
    } else {
        (base, DefaultRule::Repository)
    };
    Some(DefaultSourceUrl {
        url,
        rule,
        ignored_tag: tag.is_some() && valid_tag.is_none(),
        ignored_commit: commit.is_some() && valid_commit.is_none(),
    })
}

/// [`default_source_url`] of this binary: `CARGO_PKG_REPOSITORY`, `CARGO_PKG_VERSION` and the
/// build variables as `cargo build` saw them.
#[must_use]
pub fn compiled_default() -> Option<DefaultSourceUrl> {
    default_source_url(
        env!("CARGO_PKG_REPOSITORY"),
        env!("CARGO_PKG_VERSION"),
        option_env!("RIZZY_BUILD_TAG"),
        option_env!("RIZZY_BUILD_COMMIT"),
    )
}

/// The source URL to serve: `configured` (the setting) if set, else `default`. Logs it once
/// at `info`, and the rule-3 `warn` when the default has no exact source reference (never
/// when the setting is set). `None` when neither is there: the server must not start.
#[must_use]
pub fn served(
    configured: Option<&SourceUrl>,
    default: Option<DefaultSourceUrl>,
) -> Option<SourceUrl> {
    let url = if let Some(url) = configured {
        url.clone()
    } else {
        let default = default?;
        if default.rule == DefaultRule::Repository {
            let ignored = match (default.ignored_tag, default.ignored_commit) {
                (false, false) => "none",
                (true, false) => "RIZZY_BUILD_TAG",
                (false, true) => "RIZZY_BUILD_COMMIT",
                (true, true) => "RIZZY_BUILD_TAG,RIZZY_BUILD_COMMIT",
            };
            log::warn(
                "source_url_inexact",
                &[
                    Field::Str("advice", INEXACT_ADVICE),
                    Field::Str("ignored", ignored),
                ],
            );
        }
        default.url
    };
    log::info("source_url", &[Field::SourceUrl("url", &url)]);
    Some(url)
}

#[cfg(test)]
mod tests {
    //! ADR 0106 implementation step 2: the three rules and the startup log lines.

    use super::*;
    use crate::log::capture::lines_of;

    const REPO: &str = "https://github.com/lyuksovannyy/rizzy-vault";
    const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A default as (URL, rule, tag ignored, commit ignored).
    type Seen<'a> = (&'a str, DefaultRule, bool, bool);

    fn url(d: Option<&DefaultSourceUrl>) -> Seen<'_> {
        let d = d.unwrap();
        (d.url.as_str(), d.rule, d.ignored_tag, d.ignored_commit)
    }

    #[test]
    fn the_three_rules() {
        use DefaultRule::{Commit, Repository, Tag};
        let sha256 = "ab".repeat(32);
        let tree1 = format!("{REPO}/tree/{SHA1}");
        let tree256 = format!("{REPO}/tree/{sha256}");
        let release = format!("{REPO}/releases/tag/v1.0.0");
        let cases: &[(Option<&str>, Option<&str>, Seen<'_>)] = &[
            // Rule 1 wins over a valid commit.
            (Some("v1.0.0"), Some(SHA1), (&release, Tag, false, false)),
            (Some("v1.0.0"), None, (&release, Tag, false, false)),
            // Rule 2.
            (None, Some(SHA1), (&tree1, Commit, false, false)),
            (None, Some(&sha256), (&tree256, Commit, false, false)),
            // An invalid tag falls through to the commit.
            (Some("1.0.0"), Some(SHA1), (&tree1, Commit, true, false)),
            (Some("v1.0.1"), Some(SHA1), (&tree1, Commit, true, false)),
            // Rule 3, with what was ignored.
            (None, None, (REPO, Repository, false, false)),
            (Some(""), Some(""), (REPO, Repository, false, false)),
            (Some("1.0.0"), None, (REPO, Repository, true, false)),
            (None, Some(&SHA1[..39]), (REPO, Repository, false, true)),
            (
                None,
                Some(&format!("{SHA1}0")),
                (REPO, Repository, false, true),
            ),
            (
                None,
                Some(&SHA1.to_uppercase()),
                (REPO, Repository, false, true),
            ),
            (Some("v1.0.1"), Some("main"), (REPO, Repository, true, true)),
        ];
        for (tag, commit, want) in cases {
            let got = default_source_url(REPO, "1.0.0", *tag, *commit);
            assert_eq!(url(got.as_ref()), *want, "{tag:?} {commit:?}");
        }
    }

    #[test]
    fn an_invalid_repository_gives_no_default() {
        for repo in [
            "",
            "http://github.com/x",
            "https://github.com/x/",
            "https://github.com/x?y",
            "https://github.com/x#y",
            "git@github.com:x/y",
        ] {
            assert_eq!(
                default_source_url(repo, "1.0.0", None, Some(SHA1)),
                None,
                "{repo}"
            );
        }
        // A derived URL over the limit falls through to the next rule.
        let long = format!(
            "https://example.com/{}",
            "a".repeat(SourceUrl::MAX_LEN - 30)
        );
        let got = default_source_url(&long, "1.0.0", Some("v1.0.0"), Some(SHA1));
        assert_eq!(
            url(got.as_ref()),
            (long.as_str(), DefaultRule::Repository, false, false)
        );
    }

    #[test]
    fn the_compiled_default_is_valid() {
        let d = compiled_default().unwrap();
        assert!(d.url.as_str().starts_with(env!("CARGO_PKG_REPOSITORY")));
    }

    #[test]
    fn startup_logs_the_url_and_warns_only_for_rule_3() {
        let configured = SourceUrl::parse("https://example.com/src").unwrap();
        let inexact = default_source_url(REPO, "1.0.0", Some("1.0.0"), None);
        let exact = default_source_url(REPO, "1.0.0", None, Some(SHA1));

        // The setting wins and no warning is logged, even over a rule-3 default.
        let (got, lines) = lines_of(|| served(Some(&configured), inexact.clone()));
        assert_eq!(got.as_ref(), Some(&configured));
        assert_eq!(
            lines,
            [r#"{"event":"source_url","level":"info","ts_ms":0,"url":"https://example.com/src"}"#]
        );

        // Rule 3: the warning, naming the ignored variable, then the URL.
        let (got, lines) = lines_of(|| served(None, inexact.clone()));
        assert_eq!(got.as_ref().map(SourceUrl::as_str), Some(REPO));
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains(r#""event":"source_url_inexact""#),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains(r#""level":"warn""#));
        assert!(lines[0].contains(r#""ignored":"RIZZY_BUILD_TAG""#));
        assert!(lines[0].contains(INEXACT_ADVICE));
        assert!(lines[1].contains(&format!(r#""url":"{REPO}""#)));

        // Rule 2: no warning.
        let (got, lines) = lines_of(|| served(None, exact.clone()));
        assert_eq!(
            got.as_ref().map(SourceUrl::as_str),
            Some(format!("{REPO}/tree/{SHA1}").as_str())
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains(r#""event":"source_url""#));

        // Neither: nothing to serve, nothing logged.
        let (got, lines) = lines_of(|| served(None, None));
        assert_eq!(got, None);
        assert!(lines.is_empty());
    }
}
