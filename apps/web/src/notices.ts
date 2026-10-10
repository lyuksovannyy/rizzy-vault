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
 * How a notice names a device: "this browser" for this session, else the kind and the first
 * 8 digits of the id as the Devices pane shows them. Devices have no names. A device the
 * device list does not hold (another web session, which is never listed) is "device <id>".
 */
export function deviceLabel(id: string, devices: readonly DeviceView[], ownId: string): string {
  if (id === ownId) {
    return "this browser";
  }
  const short = id.slice(0, 8);
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

/** A stable key for one notice: its kind, item and devices. */
export function noticeKey(notice: Notice): string {
  return `${notice.kind}:${notice.item}:${notice.devices.join(",")}`;
}

/** `current` with `fresh` appended, without a notice already held (same `noticeKey`). */
export function mergeNotices(current: readonly Notice[], fresh: readonly Notice[]): Notice[] {
  const held = new Set(current.map(noticeKey));
  return [...current, ...fresh.filter((n) => !held.has(noticeKey(n)))];
}
