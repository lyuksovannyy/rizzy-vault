// SPDX-License-Identifier: AGPL-3.0-only

// The conflict chooser's wording and rules (ROADMAP §4.5 "edited on Phone and Laptop at the same
// time — keep both / pick one"; ADR 0012 §4 step 5, ADR 0018 §6): what the chooser says about
// each conflicting value, whether it offers "keep both", and the label "keep both" gives the
// copies. Pure: no wasm, no DOM.
//
// The core decides what a resolution writes (`rizzy-client`'s `conflicts` module): "pick one"
// writes the chosen value back to the field; "keep both" keeps the shown value in the field and
// moves every other value into a new custom field (hidden when the field is concealed) or, for
// a website, a new website. Both are ordinary edits, so they sync to every device.
import type { ConflictValue, DeviceView, FieldView } from "@rizzy-vault/core";

import { deviceLabel, joinNames } from "./notices.ts";

/** How the chooser names devices: `deviceLabel` over the device list and this session's id. */
export type DeviceNamer = (id: string) => string;

/** A {@link DeviceNamer} over `devices`, with `ownId` as "this browser". */
export function deviceNamer(devices: readonly DeviceView[], ownId: string): DeviceNamer {
  return (id) => deviceLabel(id, devices, ownId);
}

/** "Edited on X and Y at the same time." over the distinct devices of `values`, in order. */
export function conflictHeadline(values: readonly ConflictValue[], name: DeviceNamer): string {
  const devices = [...new Set(values.map((v) => v.device))].map(name);
  if (devices.length <= 1) {
    return "Edited in two places at the same time.";
  }
  return `Edited on ${joinNames(devices)} at the same time.`;
}

/** One value's caption: who wrote it, when, and whether it is the one shown now. */
export function conflictValueCaption(value: ConflictValue, name: DeviceNamer): string {
  const verb = value.cleared ? "Cleared" : "Edited";
  const date = new Date(value.writtenMs).toLocaleString();
  const shown = value.displayed ? " (shown now)" : "";
  return `${verb} on ${name(value.device)}, ${date}${shown}`;
}

/**
 * Whether to offer "keep both" for `field`: a text field (the core keeps text only) with at
 * least two values that are not cleared (a cleared value is never "kept"). The core refuses
 * any other case too (`invalid_edit`); this only keeps the button off where it cannot work.
 */
export function canKeepBoth(field: FieldView, values: readonly ConflictValue[]): boolean {
  if (field.kind !== "text") {
    return false;
  }
  const kept = values.filter((v) => !v.cleared);
  return kept.length >= 2 && kept.every((v) => v.kind === "text");
}

/**
 * The value "keep both" keeps in the field: the one shown now, so the field itself does not
 * change under the user; `undefined` if the shown value is a cleared one (never the case when
 * {@link canKeepBoth} holds: a cleared value never displays over a non-empty one).
 */
export function keptValue(values: readonly ConflictValue[]): ConflictValue | undefined {
  return values.find((v) => v.displayed && !v.cleared);
}

/**
 * The label of the fields "keep both" adds: the field's own label and, when exactly one value
 * moves, the device it came from ("Password (from this browser)"); "(other version)" when
 * several do, since one label serves them all.
 */
export function keepBothLabel(fieldLabel: string, values: readonly ConflictValue[], name: DeviceNamer): string {
  const moved = values.filter((v) => !v.displayed && !v.cleared);
  const only = moved.length === 1 ? moved[0] : undefined;
  return only === undefined ? `${fieldLabel} (other version)` : `${fieldLabel} (from ${name(only.device)})`;
}
