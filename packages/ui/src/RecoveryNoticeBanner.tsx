// SPDX-License-Identifier: AGPL-3.0-only

// The pending-recovery banner of ADR 0045 (owner answer 2: the web vault and the extension),
// shared by both surfaces so they say the same thing.
//
// What it shows is the server's `pending_recovery` notice: advisory, unsigned and server-set
// (INV-70). The banner is UI only. Nothing here, or in the hosts that render it, decides
// anything from it: the core verified the account answer it came with before the host ever saw
// the notice, and verifies the next one the same way whatever the notice says. The banner
// therefore says plainly that it is the server's word, and that a server can also hide one.
//
// It appears while the last account answer carried a notice and disappears with the first
// answer that does not (ADR 0045 point 3: the notice clears exactly when the server's pending
// row does, on a cancel or on the recovery's commit). It cannot be dismissed (open question 3's
// recommendation: loud, for as long as it is set).
import type { ReactNode } from "react";
import { useId } from "react";

/** The notice as the hosts hold it (`@rizzy-vault/core`'s `RecoveryNotice`). */
export interface PendingRecoveryNoticeView {
  /** When the recovery was requested, Unix milliseconds (the server's clock). */
  readonly openedAtMs: number;
  /** When its wait ends, Unix milliseconds (the server's clock). */
  readonly availableAtMs: number;
  /** When the account's previous recovery completed, if the notice says. */
  readonly lastRecoveryAtMs?: number | undefined;
}

/** The banner's sentences (`RecoveryNoticeBanner`); pure, so it is unit-tested. */
export interface RecoveryNoticeText {
  readonly title: string;
  readonly requested: string;
  readonly when: string;
  readonly consequence: string;
  readonly last: string | undefined;
  readonly advisory: string;
}

/** A time from the notice, in the user's locale; a value no date holds (a forged one) reads
 * as "an unknown time" instead of failing. */
export function noticeTime(ms: number): string {
  const date = new Date(ms);
  if (!Number.isFinite(date.getTime())) {
    return "an unknown time";
  }
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** The banner's text for `notice` at `nowMs` (this device's clock). */
export function recoveryNoticeText(notice: PendingRecoveryNoticeView, nowMs: number): RecoveryNoticeText {
  return {
    title: "Account recovery requested",
    requested: `The server reports that someone asked to recover this account with its Emergency Kit on ${noticeTime(notice.openedAtMs)}.`,
    when:
      nowMs >= notice.availableAtMs
        ? "Its waiting period is over: it can be completed now."
        : `It can be completed from ${noticeTime(notice.availableAtMs)}.`,
    consequence:
      "Whoever completes it sets a new master password and Secret Key for this account. If you did not ask for it, cancel it now from an enrolled device: run `rv recovery cancel` on a computer where this account is set up.",
    last:
      notice.lastRecoveryAtMs === undefined
        ? undefined
        : `This account was last recovered on ${noticeTime(notice.lastRecoveryAtMs)}.`,
    advisory:
      "This notice comes from the server and is not verified: a server could also hide a recovery. Your vault's own checks never depend on it.",
  };
}

export interface RecoveryNoticeBannerProps {
  readonly notice: PendingRecoveryNoticeView;
  /** This device's clock, Unix milliseconds. */
  readonly nowMs: number;
  /** A control the host adds (the web vault's "Review devices"). */
  readonly action?: ReactNode;
}

/** The banner (module docs). */
export function RecoveryNoticeBanner(props: RecoveryNoticeBannerProps) {
  const titleId = useId();
  const text = recoveryNoticeText(props.notice, props.nowMs);
  return (
    <section className="recovery-banner warning" role="alert" aria-labelledby={titleId} data-testid="recovery-banner">
      <p>
        <strong id={titleId}>{text.title}</strong>
      </p>
      <p>
        {text.requested} {text.when}
      </p>
      <p>{text.consequence}</p>
      {text.last !== undefined && <p>{text.last}</p>}
      <p className="recovery-banner-advisory">{text.advisory}</p>
      {props.action}
    </section>
  );
}
