// SPDX-License-Identifier: AGPL-3.0-only

// The late-edit and trash notices (gap 02): "An edit from <device> arrived for an item you
// deleted permanently. Restore it as a new item?" (ADR 0018 §3 "Surfacing") and "deleted on X
// while it was being edited on Y" (ADR 0012 §5 "Active wins"), worded from the ids the Worker
// hands over. Pure: no wasm, no DOM.
//
// "Already shown" lives in session memory only: the core Worker hands each notice over once
// per unlock (`takeNotices`), and the vault view keeps the handed-over notices in React state
// until the user dismisses them. Neither survives a lock or a reload, on purpose: remembering
// a shown notice across sessions would be a new record in the local cache format, which needs
// an ADR 0026 amendment first.
import type { DeviceView, Notice } from "@rizzy-vault/core";

/** Human names of the device kinds `devices` reports. */
export const DEVICE_KINDS: Readonly<Record<string, string>> = {
  "desktop-cli": "Desktop or command line",
  extension: "Browser extension",
  mobile: "Mobile",
};

/**
 * How many digits of a device id a label shows: one length, shared by `deviceLabel` below and
 * by the Devices pane's own display (`DevicesPane.tsx`), including its own-session caption, so
 * the two surfaces of this app always agree. `rv`'s notices use the same length
 * (`device_label`'s `DEVICE_LABEL_HEX_LEN`, `docs/rv.md`), though that agreement is a human
 * convention across the two codebases, not shared code.
 */
export const DEVICE_LABEL_HEX_LEN = 16;

/**
 * How a notice names a device: "this browser" for this session, else the kind and the first
 * {@link DEVICE_LABEL_HEX_LEN} digits of the id, a prefix of the full id the Devices pane
 * shows. Devices have no names. A device the device list does not hold (another web session,
 * which is never listed) is "device <id>".
 */
export function deviceLabel(id: string, devices: readonly DeviceView[], ownId: string): string {
  if (id === ownId) {
    return "this browser";
  }
  const short = id.slice(0, DEVICE_LABEL_HEX_LEN);
  const device = devices.find((d) => d.id === id);
  if (device === undefined) {
    return `device ${short}`;
  }
  return `${DEVICE_KINDS[device.kind] ?? device.kind} ${short}`;
}

/** `a`, `a and b`, `a, b and c`. */
export function joinNames(names: readonly string[]): string {
  if (names.length <= 1) {
    return names[0] ?? "";
  }
  return `${names.slice(0, -1).join(", ")} and ${names.at(-1) ?? ""}`;
}

/**
 * The notice's text. `label` names a device (`deviceLabel`); `title` is the item's name for a
 * concurrent trash (the item is still in the list), empty when it has none.
 */
export function noticeText(notice: Notice, label: (id: string) => string, title: string): string {
  if (notice.kind === "late-edit") {
    return `An edit from ${joinNames(notice.devices.map(label))} arrived for an item you deleted permanently. Restore it as a new item?`;
  }
  const [deletedOn = "", editedOn = ""] = notice.devices;
  const name = title === "" ? "An item" : `“${title}”`;
  return `${name} was deleted on ${label(deletedOn)} while it was being edited on ${label(editedOn)}. The edit kept it.`;
}

/**
 * A stable key for one notice: its kind, item, devices and (for `concurrent-trash`) its own
 * conflict id. The id tells a second, genuinely distinct race between the same two devices on
 * the same item apart from the first, so it is not merged away as a duplicate; `late-edit` has
 * no conflict id, so its key is unchanged (kind, item and devices only).
 */
export function noticeKey(notice: Notice): string {
  return `${notice.kind}:${notice.item}:${notice.devices.join(",")}:${notice.conflictId ?? ""}`;
}

/** `current` with `fresh` appended, without a notice already held (same `noticeKey`). */
export function mergeNotices(current: readonly Notice[], fresh: readonly Notice[]): Notice[] {
  const held = new Set(current.map(noticeKey));
  return [...current, ...fresh.filter((n) => !held.has(noticeKey(n)))];
}
