// How the web vault names a device in a notice ("An edit from <device> arrived…", "deleted on
// <X> while it was being edited on <Y>", ADR 0012 §5, ADR 0018 §3). Devices have no names in
// M1: an enrolled device is named by its kind and the start of its id, as the Devices pane
// lists it; this browser session by itself; any other id is a web vault session, which is
// ephemeral and never in the device list (DevicesPane module docs).
import type { DeviceView } from "@rizzy-vault/core";

/** Human names of the device kinds. */
export const DEVICE_KINDS: Readonly<Record<string, string>> = {
  "desktop-cli": "Desktop or command line",
  extension: "Browser extension",
  mobile: "Mobile",
};

/** The name of device `id` (module docs). */
export function deviceName(id: string, devices: readonly DeviceView[], ownId: string): string {
  if (id === ownId) {
    return "this browser";
  }
  const short = `${id.slice(0, 8)}…`;
  const device = devices.find((d) => d.id === id);
  if (device === undefined) {
    return `a web vault session (${short})`;
  }
  return `${DEVICE_KINDS[device.kind] ?? device.kind} (${short})`;
}

/** Several device names as one phrase: "A", "A and B", "A, B and C". */
export function deviceNames(ids: readonly string[], devices: readonly DeviceView[], ownId: string): string {
  const names = ids.map((id) => deviceName(id, devices, ownId));
  if (names.length <= 1) {
    return names[0] ?? "another device";
  }
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1] ?? ""}`;
}
