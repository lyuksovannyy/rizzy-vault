// The late-edit notices (ADR 0018 §3 "Surfacing", ADR 0012 §5 "Late ops after a purge"): an
// edit that another device made while this item was being deleted for good arrived after the
// purge. The core keeps those values in the purged item's tombstone; this shows, once per
// session, "An edit from <device> arrived for an item you deleted permanently. Restore it as a
// new item?", with the type the user confirms for the new item (ADR 0018 §3: "Restoring creates
// a new item"). Dismissing hides the notice for the edits it named for the rest of the session;
// the core keeps which ones were shown in memory only (`rizzy-client`'s `trash` module docs).
import type { DeviceView, ItemType, LateEdit } from "@rizzy-vault/core";
import { useToast } from "@rizzy-vault/ui";
import { useEffect, useId, useState } from "react";

import { deviceNames } from "../device-names.ts";
import { CREATABLE_TYPES } from "../fields.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** One notice, with its type choice and its two actions. */
function LateEditNotice(props: {
  readonly ctx: VaultContext;
  readonly edit: LateEdit;
  readonly devices: readonly DeviceView[];
  readonly onDone: () => void;
}) {
  const { ctx, edit } = props;
  const [itemType, setItemType] = useState<ItemType>("login");
  const { busy, error, run } = useAction();
  const { notify } = useToast();
  const selectId = useId();
  const from = deviceNames(edit.devices, props.devices, ctx.session.deviceId);

  const restore = () =>
    void run(async () => {
      await ctx.client.call("restoreLateEdit", edit.id, itemType);
      props.onDone();
      await ctx.afterWrite();
      notify("success", "Restored as a new item.");
    });

  const dismiss = () =>
    void run(async () => {
      await ctx.client.call("dismissLateEdit", edit.id);
      props.onDone();
    });

  return (
    <div className="notice late-edit" role="status" data-late-edit={edit.id}>
      <p>
        An edit from {from} arrived for an item you deleted permanently. Restore it as a new item?
      </p>
      <div className="actions">
        {!ctx.session.readOnly && (
          <>
            <label htmlFor={selectId} className="sr-only">
              Type of the new item
            </label>
            <select
              id={selectId}
              className="late-edit-type"
              value={itemType}
              disabled={busy}
              onChange={(e) => setItemType(e.currentTarget.value as ItemType)}
            >
              {CREATABLE_TYPES.map((t) => (
                <option key={t.type} value={t.type}>
                  {t.label}
                </option>
              ))}
            </select>
            <button type="button" disabled={busy} onClick={restore}>
              Restore as new item
            </button>
          </>
        )}
        <button type="button" className="secondary" disabled={busy} onClick={dismiss}>
          Dismiss
        </button>
      </div>
      <ErrorText code={error} />
    </div>
  );
}

/** Every late-edit notice of the vault (module docs), reloaded after each sync. */
export function LateEditNotices(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [edits, setEdits] = useState<{ edits: LateEdit[]; devices: DeviceView[] } | undefined>();
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let live = true;
    ctx.client.call("lateEdits").then(
      async (found) => {
        // The device list only names the devices; the notices show without it.
        const devices = found.length === 0 ? [] : await ctx.client.call("devices").catch(() => []);
        if (live) {
          setEdits({ edits: found, devices });
        }
      },
      () => live && setEdits(undefined),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, reload]);

  if (edits === undefined || edits.edits.length === 0) {
    return null;
  }
  return (
    <div className="late-edits" aria-label="Edits after a permanent delete">
      {edits.edits.map((e) => (
        <LateEditNotice key={e.id} ctx={ctx} edit={e} devices={edits.devices} onDone={() => setReload((r) => r + 1)} />
      ))}
    </div>
  );
}
