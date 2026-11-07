// SPDX-License-Identifier: AGPL-3.0-only

// The "Pattern" input of a website whose match mode is Regex (ADR 0097 §3.6). The core checks
// the pattern as it is typed (`uriPatternCheck`, over `rizzy_match::pattern::compile` and
// `is_anchored`): an invalid one names its `PatternError` kind and cannot be saved
// (`regex_invalid`); an unanchored one shows ADR 0097's warning and can still be saved. A synced
// pattern this build finds invalid is shown as invalid and is never rewritten without a user
// edit (the editor writes `pattern` only when the text or the mode changed).
import type { UriPatternError } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { useEffect, useId, useState } from "react";

import type { CoreClient } from "../core-client.ts";
import { MATCH_MODE_REGEX } from "../fields.ts";

/** What the core says about one pattern. */
export interface PatternStatus {
  readonly error: UriPatternError | undefined;
  readonly anchored: boolean;
}

/** Whether a match-mode select's decimal value is Regex. */
export function isRegexMode(value: string): boolean {
  return Number.parseInt(value, 10) === MATCH_MODE_REGEX;
}

/** The message of an invalid pattern, naming its kind (ADR 0097 §3.6). */
export function patternErrorText(error: UriPatternError): string {
  switch (error) {
    case "empty":
      return t("matching.patternErrorEmpty");
    case "too_long":
      return t("matching.patternErrorTooLong");
    case "not_ascii":
      return t("matching.patternErrorNotAscii");
    case "invalid":
      return t("matching.patternErrorInvalid");
  }
}

/** The pattern input of one website row: `label` names the website (`Website 2`). */
export function UriPatternField(props: {
  readonly client: CoreClient;
  readonly label: string;
  readonly value: string;
  readonly disabled?: boolean;
  readonly onChange: (value: string) => void;
}) {
  const { client, value } = props;
  const [status, setStatus] = useState<PatternStatus | undefined>();
  const messageId = useId();
  useEffect(() => {
    let live = true;
    client.call("uriPatternCheck", value).then(
      (s) => {
        if (live) {
          setStatus(s);
        }
      },
      () => {
        if (live) {
          setStatus(undefined);
        }
      },
    );
    return () => {
      live = false;
    };
  }, [client, value]);
  const error = status?.error;
  const unanchored = status !== undefined && error === undefined && !status.anchored;
  return (
    <div className="uri-pattern">
      <input
        type="text"
        autoComplete="off"
        spellCheck={false}
        required
        aria-label={`${props.label} ${t("matching.pattern").toLowerCase()}`}
        aria-invalid={error !== undefined && value !== "" ? true : undefined}
        aria-describedby={error !== undefined || unanchored ? messageId : undefined}
        placeholder={t("matching.pattern")}
        value={value}
        disabled={props.disabled}
        onChange={(e) => props.onChange(e.currentTarget.value)}
      />
      {error !== undefined && (
        <p id={messageId} className="error small" data-code="regex_invalid" data-kind={error}>
          {patternErrorText(error)}
        </p>
      )}
      {unanchored && (
        <p id={messageId} className="muted small" data-warning="pattern-unanchored">
          {t("matching.patternUnanchored")}
        </p>
      )}
    </div>
  );
}
