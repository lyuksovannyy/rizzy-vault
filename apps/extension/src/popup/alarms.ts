// SPDX-License-Identifier: AGPL-3.0-only

// The words for the durable device's alarms (ADR 0026 §3 kind 7; `rizzy-wasm`'s `alarms`
// module), as `rv` says them (`crates/rizzy-cli/src/error.rs`). The codes are the core's.

/** The alarm codes the core names. */
export const ALARM_CODES = [
  "rollback",
  "fork",
  "identity_change_unconfirmed",
  "device_state_outdated",
  "alarm_unknown",
] as const;

/** Whether `code` names an alarm (a sync the core refused under one fails with it). */
export function isAlarmCode(code: string): boolean {
  return (ALARM_CODES as readonly string[]).includes(code);
}

/** What alarm `code` means, in a sentence fragment. */
export function alarmDescription(code: string): string {
  switch (code) {
    case "rollback":
      return "possible rollback by the server";
    case "fork":
      return "the server has shown two versions of this account";
    case "identity_change_unconfirmed":
      return "the account's identity keys changed and this device has not confirmed it";
    case "device_state_outdated":
      return "the local data is older than this device's own history";
    default:
      return "an alarm this version of the extension does not know (update the extension)";
  }
}
