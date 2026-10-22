// SPDX-License-Identifier: AGPL-3.0-only

// The quick-access command palette (Ctrl/Cmd+K; ROADMAP §4.2/§4.5 "quick-access / command
// palette"): search the decrypted, in-memory item list by title, username, URL host or tag
// (`palette.ts`'s `itemRowsFor`, reusing `fields.ts`'s `matches` — the same fields the item
// list itself searches), open an item, copy its username/password/TOTP code, or jump straight
// to one of the vault's own views (`navCommands`, built by `VaultView.tsx` from the same
// sidebar entries it renders). Never sends anything to the server: `items`, `reveal` and `totp`
// are all calls into the already-running core Worker, the same calls `ItemsPane.tsx` and
// `ItemView.tsx` already make.
//
// One ARIA 1.2 "editable combobox with list autocomplete" (WAI-ARIA APG): the text input is the
// only focusable element and carries `role="combobox"`; the results are a sibling
// `role="listbox"`, each row `role="option"`; the input's `aria-activedescendant` names the
// highlighted option. Arrow keys move the highlight (`shortcuts.ts`'s `moveListSelection`,
// shared with the item list's own roving selection), Enter runs the highlighted row, Escape
// closes. Tab/Shift+Tab are swallowed rather than left to move focus to the backdrop's Cancel
// button: that button stays mouse-only, the same trade-off a browser's own address bar makes,
// so the combobox never loses focus to an element outside it while open.
//
// `CommandPalette` itself is a thin wrapper that mounts `Dialog` fresh on every open, rather
// than keeping one instance mounted and resetting its state through an effect keyed on `open`:
// a fresh mount's `useState("")` starts clean by construction, with nothing to race against a
// fast reopen-then-type. The effect version had exactly that race — opening and immediately
// filling the search box, back to back with no yield in between (a fast real typist, or a
// Playwright `fill()` right after `press("Control+k")`), could have the open transition's own
// state-reset effect run *after* the keystroke's `onChange`, silently discarding it — found via
// this component's own Playwright coverage (`e2e/command-palette.spec.ts`), fixed by removing
// the reset instead of trying to win the race.
import type { ItemSummary } from "@rizzy-vault/core";
import { IconSearch, TypeIcon, useToast } from "@rizzy-vault/ui";
import { type KeyboardEvent, type ReactNode, useEffect, useId, useMemo, useRef, useState } from "react";

import { type PaletteItemAction, actionLabel, itemRowsFor, matchesLabel } from "../palette.ts";
import { moveListSelection } from "../shortcuts.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** One "jump to a view" command (built by `VaultView.tsx` from its own sidebar entries, so the
 * palette never lists a view the sidebar does not also offer). */
export interface PaletteNavCommand {
  readonly id: string;
  readonly label: string;
  readonly icon: ReactNode;
  readonly run: () => void;
}

/** One row of the palette's own flat results list, built from either a `PaletteNavCommand` or
 * an item action row (`palette.ts`'s `PaletteItemRow`). */
interface Row {
  readonly id: string;
  readonly label: string;
  readonly sub?: string | undefined;
  readonly icon: ReactNode;
  readonly run: () => void | Promise<void>;
}

function itemSub(item: ItemSummary): string {
  return item.username ?? item.itemType;
}

/** The command palette (module docs). Renders nothing while `open` is false; mounts a fresh
 * {@link Dialog} instance each time it becomes true. */
export function CommandPalette(props: {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly ctx: VaultContext;
  readonly navCommands: readonly PaletteNavCommand[];
  readonly onOpenItem: (id: string) => void;
}) {
  if (!props.open) {
    return null;
  }
  return (
    <Dialog
      onClose={props.onClose}
      ctx={props.ctx}
      navCommands={props.navCommands}
      onOpenItem={props.onOpenItem}
    />
  );
}

/** The palette's actual content (module docs above `CommandPalette`): a fresh instance per
 * open, so its `query`/`activeIndex`/`items` state always starts clean with no reset effect. */
function Dialog(props: {
  readonly onClose: () => void;
  readonly ctx: VaultContext;
  readonly navCommands: readonly PaletteNavCommand[];
  readonly onOpenItem: (id: string) => void;
}) {
  const { onClose, ctx, navCommands, onOpenItem } = props;
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<readonly ItemSummary[]>([]);
  const [activeIndex, setActiveIndex] = useState(0);
  const { error, run } = useAction();
  const { notify } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const previouslyFocused = useRef<Element | null>(null);
  const listboxId = useId();

  useEffect(() => {
    previouslyFocused.current = document.activeElement;
    let live = true;
    // Active items only (module docs): a trashed item's "open" would land on a view with no
    // edit/copy path of its own worth surfacing here, and `palette.ts`'s own trash filter would
    // drop it from the results anyway.
    ctx.client.call("items", false).then(
      (list) => {
        if (live) {
          setItems(list);
        }
      },
      () => {
        if (live) {
          setItems([]);
        }
      },
    );
    // The dialog has only just mounted this render; queue the focus for the frame after it
    // lands, the same pattern `VaultView.tsx`'s own `focus-search` shortcut uses.
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      live = false;
      cancelAnimationFrame(frame);
      if (previouslyFocused.current instanceof HTMLElement) {
        previouslyFocused.current.focus();
      }
    };
    // Runs exactly once, for this instance's one mount/unmount (module docs above `Dialog`):
    // `ctx.client` is stable for the component's lifetime, so an empty dependency array would
    // behave the same; it is listed anyway so a future `ctx` prop change is not silently missed.
  }, [ctx.client]);

  const navRows: readonly Row[] = useMemo(
    () =>
      navCommands.filter((c) => matchesLabel(c.label, query)).map((c) => ({
        id: `nav-${c.id}`,
        label: c.label,
        icon: c.icon,
        run: () => {
          c.run();
          onClose();
        },
      })),
    [navCommands, query, onClose],
  );

  const itemRows: readonly Row[] = useMemo(
    () =>
      itemRowsFor(items, query).map(({ action, item }) => itemRow(action, item, ctx, onOpenItem, onClose, notify)),
    [items, query, ctx, onOpenItem, onClose, notify],
  );

  const rows = useMemo(() => [...navRows, ...itemRows], [navRows, itemRows]);
  // Clamped here, rather than re-synced through an effect: `rows` can shrink (a keystroke
  // narrows the results) in the same render that would otherwise leave `activeIndex` pointing
  // past the end.
  const safeActiveIndex = rows.length === 0 ? -1 : Math.min(activeIndex, rows.length - 1);

  const runRow = (row: Row | undefined) => {
    if (row === undefined) {
      return;
    }
    void run(async () => {
      await row.run();
    });
  };

  const onInputKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "Tab") {
      // Module docs: focus stays on this one input while the palette is open.
      e.preventDefault();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const next = moveListSelection(e.key, rows.length, safeActiveIndex);
      if (next !== undefined) {
        e.preventDefault();
        setActiveIndex(next);
      }
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      runRow(rows[safeActiveIndex]);
    }
  };

  return (
    <div className="overlay">
      <button type="button" className="dialog-backdrop" aria-label="Close" onClick={onClose} />
      <div className="panel dialog command-palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="command-palette-combobox">
          <IconSearch />
          <input
            ref={inputRef}
            role="combobox"
            aria-expanded="true"
            aria-controls={listboxId}
            aria-autocomplete="list"
            aria-activedescendant={safeActiveIndex >= 0 ? `${listboxId}-${safeActiveIndex}` : undefined}
            aria-label="Command palette"
            placeholder="Search items, or jump to a view…"
            spellCheck={false}
            autoComplete="off"
            value={query}
            onChange={(e) => {
              setQuery(e.currentTarget.value);
              setActiveIndex(0);
            }}
            onKeyDown={onInputKeyDown}
          />
        </div>
        <ErrorText code={error} />
        <ul id={listboxId} role="listbox" aria-label="Commands">
          {rows.map((row, index) => (
            <li
              key={row.id}
              id={`${listboxId}-${index}`}
              role="option"
              aria-selected={index === safeActiveIndex}
              className={index === safeActiveIndex ? "row selected" : "row"}
              onMouseEnter={() => setActiveIndex(index)}
              onClick={() => runRow(row)}
            >
              <span className="row-icon" aria-hidden="true">
                {row.icon}
              </span>
              {/* The option's accessible name is its visible text (WCAG 2.5.3 "label in
                  name"): the title, then the sub line, which the column layout separates. */}
              <span className="row-text">
                <span className="row-title">{row.label}</span>
                {row.sub !== undefined && <span className="row-sub">{row.sub}</span>}
              </span>
            </li>
          ))}
        </ul>
        {rows.length === 0 && <p className="muted empty-state">Nothing matches.</p>}
      </div>
    </div>
  );
}

/** Builds one item-action row (module docs above). Kept as a plain function, not inlined in the
 * `useMemo` above, so each action's own async work and error handling reads in one place. */
function itemRow(
  action: PaletteItemAction,
  item: ItemSummary,
  ctx: VaultContext,
  onOpenItem: (id: string) => void,
  onClose: () => void,
  notify: (kind: "success" | "error" | "info", message: string) => void,
): Row {
  const title = item.title === "" ? "(untitled)" : item.title;
  const label = `${actionLabel(action)} — ${title}`;
  const run = async (): Promise<void> => {
    switch (action) {
      case "open":
        onOpenItem(item.id);
        onClose();
        return;
      case "copy-username":
        await ctx.clipboard.copy(item.username ?? "");
        notify("success", `Username copied for ${title}.`);
        onClose();
        return;
      case "copy-password":
        await ctx.clipboard.copy(await ctx.client.call("reveal", item.id, "login.password"));
        notify("success", `Password copied for ${title}.`);
        onClose();
        return;
      case "copy-totp": {
        const code = await ctx.client.call("totp", item.id);
        await ctx.clipboard.copy(code.code);
        notify("success", `TOTP code copied for ${title}.`);
        onClose();
      }
    }
  };
  // `run` itself calls `onClose()` only on its own success path (above); a rejection propagates
  // to `Dialog`'s `useAction.run` uncaught, which records the code and leaves the palette open
  // (`ErrorText` then shows it, the same `codeOf`/`messageFor` convention every other failed
  // action in this app uses) — so the user sees what failed and can try another row, rather
  // than the palette vanishing on a reveal or clipboard failure.
  return {
    id: `item-${action}-${item.id}`,
    label,
    sub: action === "open" ? itemSub(item) : undefined,
    icon: <TypeIcon type={item.itemType} />,
    run,
  };
}
