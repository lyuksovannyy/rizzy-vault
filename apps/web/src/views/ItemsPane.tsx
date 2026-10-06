// The item list with search, and the selected item's view or editor. In the trash, the list
// shows trashed items, and the view offers restore and purge instead of edit.
//
// The sidebar's item filters (`Scope`, VaultView.tsx) narrow the list by favorite or type, on
// top of the free-text search below; both apply over the same `ItemSummary[]` this pane already
// loads, so neither needs another call to the core.
import type { ItemSummary, ItemType } from "@rizzy-vault/core";
import { IconStarFilled, IconStarOutline, TypeIcon } from "@rizzy-vault/ui";
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import { CREATABLE_TYPES, matches } from "../fields.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText } from "./common.tsx";
import { ItemEditor } from "./ItemEditor.tsx";
import { ItemView } from "./ItemView.tsx";

/** What the right-hand side shows. */
type Detail =
  | { readonly kind: "none" }
  | { readonly kind: "view"; readonly id: string }
  | { readonly kind: "edit"; readonly id: string }
  | { readonly kind: "new"; readonly itemType: ItemType };

/** A sidebar item filter, applied over the trash/non-trash list this pane already loads. */
export type Scope =
  | { readonly kind: "all" }
  | { readonly kind: "favorites" }
  | { readonly kind: "type"; readonly itemType: ItemType };

/** Whether `item` passes the sidebar's filter. Exported for its own test (module docs). */
export function inScope(item: ItemSummary, scope: Scope): boolean {
  switch (scope.kind) {
    case "all":
      return true;
    case "favorites":
      return item.favorite;
    case "type":
      return item.itemType === scope.itemType;
  }
}

/** The label of an empty section, and the type to offer creating first.
 *
 * `vaultHasAny` is whether the whole (unfiltered, unsearched) trash/non-trash list is non-empty;
 * `scopeHasAny` is whether the sidebar-scoped list (before the free-text search) is non-empty;
 * `searching` is whether a search query narrows it further. These are kept as separate signals,
 * not collapsed into one, because the three cases need different copy: nothing in the vault at
 * all, the vault has items but none of this scope, and this scope has items but none match the
 * search. Exported for its own test (module docs). */
export function emptyState(
  scope: Scope,
  trash: boolean,
  vaultHasAny: boolean,
  scopeHasAny: boolean,
  searching = false,
): { readonly text: string; readonly cta?: ItemType } {
  if (trash) {
    return { text: "The trash is empty." };
  }
  if (!vaultHasAny) {
    return { text: "No items yet.", cta: scope.kind === "type" ? scope.itemType : "login" };
  }
  if (!scopeHasAny) {
    if (scope.kind === "favorites") {
      return { text: "No favorites yet. Star an item to find it here." };
    }
    if (scope.kind === "type") {
      return { text: "Nothing of this type yet.", cta: scope.itemType };
    }
    // "all" scope always has items whenever vaultHasAny is true; unreachable in practice.
    return { text: "Nothing matches." };
  }
  if (searching) {
    if (scope.kind === "favorites") {
      return { text: "No favorites match your search." };
    }
    if (scope.kind === "type") {
      return { text: "Nothing of this type matches your search." };
    }
    return { text: "Nothing matches." };
  }
  return { text: "Nothing matches." };
}

/** The list and the detail (module docs). */
export function ItemsPane(props: { readonly ctx: VaultContext; readonly trash: boolean; readonly scope: Scope }) {
  const { ctx, trash, scope } = props;
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const [detail, setDetail] = useState<Detail>({ kind: "none" });
  const [error, setError] = useState<string | undefined>();
  const [localRevision, setLocalRevision] = useState(0);

  useEffect(() => {
    let live = true;
    ctx.client.call("items", trash).then(
      (list) => {
        if (live) {
          setItems(list);
          setError(undefined);
        }
      },
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, trash, localRevision]);

  useEffect(() => setDetail({ kind: "none" }), [trash, scope]);

  const inFilter = items.filter((i) => inScope(i, scope));
  const shown = inFilter
    .filter((i) => matches(i, query))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));
  const empty = emptyState(scope, trash, items.length > 0, inFilter.length > 0, query !== "");

  /** After a write: refresh the list now, and sync. */
  const written = async (next: Detail) => {
    setDetail(next);
    setLocalRevision((r) => r + 1);
    await ctx.afterWrite();
  };

  return (
    <div className="items">
      <div className="item-list">
        <div className="item-list-toolbar">
          <input
            type="search"
            aria-label="Search items"
            placeholder="Search"
            spellCheck={false}
            autoComplete="off"
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
          />
          <span className="item-count" aria-live="polite">
            {shown.length} {shown.length === 1 ? "item" : "items"}
          </span>
        </div>
        {!trash && !ctx.session.readOnly && (
          <div className="new-item">
            {CREATABLE_TYPES.map((t) => (
              <button
                key={t.type}
                type="button"
                className="secondary small"
                onClick={() => setDetail({ kind: "new", itemType: t.type })}
              >
                New {t.label.toLowerCase()}
              </button>
            ))}
          </div>
        )}
        <ErrorText code={error} />
        {shown.length === 0 ? (
          // No extra call-to-action button here: the "New {type}" cluster above already offers
          // every creatable type whenever one could apply (not trash, writable), so a second
          // button for the same action would just duplicate it (`empty.cta` names which type
          // fits best, for a future single "New item" picker that does not list every type
          // inline — not_done, VaultView.tsx module docs).
          <div className="empty-state">
            <p className="muted">{empty.text}</p>
          </div>
        ) : (
          <ul aria-label={trash ? "Trashed items" : "Items"}>
            {shown.map((i) => (
              <li key={i.id}>
                <button
                  type="button"
                  className={detail.kind !== "none" && detail.kind !== "new" && detail.id === i.id ? "row selected" : "row"}
                  onClick={() => setDetail({ kind: "view", id: i.id })}
                >
                  <span className="row-icon">
                    <TypeIcon type={i.itemType} />
                  </span>
                  <span className="row-text">
                    <span className="row-title">{i.title === "" ? "(untitled)" : i.title}</span>
                    <span className="row-sub">{i.username ?? i.itemType}</span>
                  </span>
                  {i.favorite ? (
                    <span className="row-favorite" aria-label="favorite">
                      <IconStarFilled />
                    </span>
                  ) : (
                    <span className="row-favorite row-favorite-hidden" aria-hidden="true">
                      <IconStarOutline />
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="item-detail">
        {detail.kind === "view" && (
          <ItemView
            key={`${detail.id}-${ctx.revision}-${localRevision}`}
            ctx={ctx}
            id={detail.id}
            onEdit={() => setDetail({ kind: "edit", id: detail.id })}
            onWritten={(gone) => written(gone ? { kind: "none" } : detail)}
          />
        )}
        {detail.kind === "edit" && (
          <ItemEditor
            key={`edit-${detail.id}`}
            ctx={ctx}
            id={detail.id}
            onCancel={() => setDetail({ kind: "view", id: detail.id })}
            onSaved={(id) => written({ kind: "view", id })}
          />
        )}
        {detail.kind === "new" && (
          <ItemEditor
            key={`new-${detail.itemType}`}
            ctx={ctx}
            newType={detail.itemType}
            onCancel={() => setDetail({ kind: "none" })}
            onSaved={(id) => written({ kind: "view", id })}
          />
        )}
      </div>
    </div>
  );
}
