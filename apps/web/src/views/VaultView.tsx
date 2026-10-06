// The unlocked vault: the header (account, sync state, lock), and the sections.
//
// Writes go to the core's memory first; the vault syncs right after each write, every five
// minutes, and on demand, so that a lock or a reload loses as little as possible (a lock
// loses unsent changes: `unsentChanges`).
//
// Locking (THREAT_MODEL §7.1 "I", INV-21) never waits on anything that can hang: the Worker
// gets `lock` first (it jumps the Worker's queue and aborts any request in flight), the UI
// drops the vault at once, and only then does the clipboard clear start, unawaited
// (`clipboard.ts`; a clipboard call can wait on a browser prompt).
//
// It locks itself after `IDLE_LOCK_MS` without input (`autolock.ts`). When changes are still
// unsent then, it first tries one sync, bounded by `FINAL_SYNC_MS`, and locks in any case;
// changes that still did not reach the server are counted in the lock notice.
import type { ItemType } from "@rizzy-vault/core";
import {
  ConfirmDialog,
  IconAccount,
  IconAllItems,
  IconChevronDown,
  IconGenerator,
  IconLock,
  IconMenu,
  IconSettings,
  IconStarFilled,
  IconTag,
  IconTransfer,
  IconTrash,
  TypeIcon,
  isAnyModalOpen,
} from "@rizzy-vault/ui";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { watchIdle } from "../autolock.ts";
import { ClipboardGuard, browserClipboard } from "../clipboard.ts";
import { type CoreClient, codeOf } from "../core-client.ts";
import { useDismissableMenu } from "../dismissable-menu.ts";
import { CREATABLE_TYPES, tagCounts } from "../fields.ts";
import { type GeneratorMemory, useGeneratorMemory } from "../generator-memory.ts";
import type { SessionInfo } from "../protocol.ts";
import { shortcutFor } from "../shortcuts.ts";
import { GeneratorPane } from "./GeneratorPane.tsx";
import { ItemsPane, type Scope } from "./ItemsPane.tsx";
import { SettingsView } from "./SettingsView.tsx";
import { ShortcutsHelp } from "./ShortcutsHelp.tsx";
import { TransferPane } from "./TransferPane.tsx";
import { ErrorText } from "./common.tsx";

/** How often the vault syncs on its own. */
const SYNC_EVERY_MS = 5 * 60_000;

/** How long the auto-lock waits for its last sync before it locks anyway. */
export const FINAL_SYNC_MS = 10_000;

/** The "all items" scope, as one stable object: `ItemsPane`'s effect that clears the open
 * detail depends on `scope` by identity (`[trash, scope]`), so a scope recreated on every
 * render — a `{ kind: "all" }` literal written straight into JSX, which is a new object each
 * time `VaultView` re-renders (`sync()` alone re-renders it every 5 minutes and after every
 * write) — would clear the open item on every one of those renders, not only on an actual
 * filter change. Every "all items" scope in this file is this same constant. */
const ALL_SCOPE: Scope = { kind: "all" };

/** The item-filter entries of the sidebar's top group (module docs below `Scope`). */
const ITEM_FILTERS: readonly { readonly scope: Scope; readonly label: string; readonly icon: ItemType | "all" | "favorites" }[] = [
  { scope: ALL_SCOPE, label: "All items", icon: "all" },
  { scope: { kind: "favorites" }, label: "Favorites", icon: "favorites" },
  ...CREATABLE_TYPES.map((t) => ({ scope: { kind: "type", itemType: t.type } as Scope, label: t.label, icon: t.type })),
];

/** The sidebar's lower group: panes that are not the item list. Devices and Two-factor are no
 * longer their own entries (redesign slice 2, item 5): both now live inside the one Settings
 * view, alongside Appearance. */
const OTHER_SECTIONS = [
  { id: "generator", label: "Generator", icon: <IconGenerator /> },
  { id: "transfer", label: "Export and import", icon: <IconTransfer /> },
] as const;

type Section = "items" | "trash" | "settings" | (typeof OTHER_SECTIONS)[number]["id"];

/** What the views below the header use. */
export interface VaultContext {
  readonly client: CoreClient;
  readonly clipboard: ClipboardGuard;
  readonly session: SessionInfo;
  /** Syncs after a write; the view refreshes from `revision`. */
  readonly afterWrite: () => Promise<void>;
  /** Bumped after every sync, so lists reload. */
  readonly revision: number;
  /** The generator's in-memory, session-only state (generator-memory.ts module docs). */
  readonly generator: GeneratorMemory;
}

/** The vault (module docs). */
export function VaultView(props: {
  readonly client: CoreClient;
  readonly loginName: string;
  readonly initialSession: SessionInfo;
  readonly onLocked: (notice?: string) => void;
}) {
  const { client, onLocked } = props;
  const [session, setSession] = useState(props.initialSession);
  const [section, setSection] = useState<Section>("items");
  const [scope, setScope] = useState<Scope>(ALL_SCOPE);
  /** Narrow screens: the sidebar is a slide-over, closed by default (item 1, module docs). */
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | undefined>();
  const [revision, setRevision] = useState(0);
  /** Tag names and counts over the active (non-trash) items, for the sidebar's Tags group
   * (item 6). Loaded here, separately from `ItemsPane`'s own list, because the sidebar needs
   * it whichever section is showing, not only while the item list itself is on screen. */
  const [tags, setTags] = useState<readonly { readonly tag: string; readonly count: number }[]>([]);
  const clipboard = useMemo(() => new ClipboardGuard(browserClipboard), []);
  const generator = useGeneratorMemory();
  const lockedRef = useRef(false);
  /** The latest session state, for the auto-lock (which runs outside a render). */
  const sessionRef = useRef(props.initialSession);

  const lock = useCallback(
    (notice?: string) => {
      if (lockedRef.current) {
        return;
      }
      lockedRef.current = true;
      // Posted synchronously; nothing here waits for the answer (module docs).
      void client.call("lock").catch(() => undefined);
      onLocked(notice);
      void clipboard.clearNow();
    },
    [client, clipboard, onLocked],
  );

  /** Records a new session state. */
  const update = useCallback((next: SessionInfo) => {
    sessionRef.current = next;
    setSession(next);
  }, []);

  const sync = useCallback(async () => {
    setSyncing(true);
    try {
      update(await client.call("sync"));
      setSyncError(undefined);
    } catch (e) {
      const code = codeOf(e);
      setSyncError(code);
      if (code === "locked" || code === "core_crashed") {
        lock();
      }
    } finally {
      setSyncing(false);
      setRevision((r) => r + 1);
    }
  }, [client, lock, update]);

  /** The idle lock (module docs): one bounded last sync for unsent changes, then the lock. */
  const autoLock = useCallback(async () => {
    if (lockedRef.current) {
      return;
    }
    let unsent = sessionRef.current.unsentChanges;
    if (unsent > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), FINAL_SYNC_MS);
      });
      try {
        const after = await Promise.race([client.call("sync"), timeout]);
        if (after !== undefined) {
          unsent = after.unsentChanges;
        }
      } catch {
        // Offline or refused: the count stays, and the notice says so.
      } finally {
        clearTimeout(timer);
      }
    }
    lock(
      unsent > 0
        ? `Locked after inactivity. ${unsent} change(s) could not be saved to the server and are lost.`
        : "Locked after inactivity.",
    );
  }, [client, lock]);

  useEffect(() => {
    void sync();
    const timer = setInterval(() => void sync(), SYNC_EVERY_MS);
    const stopIdle = watchIdle(() => void autoLock());
    const onHide = () => void clipboard.clearNow();
    window.addEventListener("pagehide", onHide);
    return () => {
      clearInterval(timer);
      stopIdle();
      window.removeEventListener("pagehide", onHide);
    };
  }, [sync, autoLock, clipboard]);

  useEffect(() => {
    let live = true;
    client.call("items", false).then(
      (list) => live && setTags(tagCounts(list)),
      () => undefined, // The sidebar's Tags group just stays empty; ItemsPane shows the real error.
    );
    return () => {
      live = false;
    };
  }, [client, revision]);

  /** Lock-with-unsaved-changes now confirms through the accessible dialog (redesign slice 2,
   * item 2), not `window.confirm`. */
  const [confirmLock, setConfirmLock] = useState(false);
  const lockNow = () => {
    if (session.unsentChanges > 0) {
      setConfirmLock(true);
      return;
    }
    lock();
  };

  /** The account menu (top bar) and the shortcuts help dialog, and a one-shot signal that asks
   * the open `ItemsPane` to start a new item (the `N` shortcut; module docs, `shortcuts.ts`). */
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [newItemSignal, setNewItemSignal] = useState(0);
  const accountMenuAnchorRef = useRef<HTMLSpanElement>(null);
  const accountMenuTriggerRef = useRef<HTMLButtonElement>(null);
  const closeAccountMenu = useCallback(() => setAccountMenuOpen(false), []);
  // Outside-click dismissal (Escape is already handled by the global shortcut switch below,
  // which also returns focus — this hook only adds the outside-click half for this menu).
  useDismissableMenu(accountMenuOpen, closeAccountMenu, accountMenuAnchorRef, accountMenuTriggerRef, false);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      // A `ConfirmDialog` instance may be open anywhere in the tree right now — this view's own
      // `confirmLock`, or `ItemView`'s trash/purge confirm, or `TwoFactorPane`'s disable confirm,
      // none of which this view can see directly. While one is open, global shortcuts must stay
      // silent: `N` must not mount a new-item editor behind it, `?` must not open the shortcuts
      // dialog on top of it, and plain navigation shortcuts must not steal focus away from it.
      // The dialog handles its own Escape and focus trap.
      if (isAnyModalOpen()) {
        return;
      }
      const target = e.target;
      const action = shortcutFor({
        key: e.key,
        ctrlKey: e.ctrlKey,
        metaKey: e.metaKey,
        altKey: e.altKey,
        shiftKey: e.shiftKey,
        target:
          target instanceof HTMLElement
            ? { tagName: target.tagName, isContentEditable: target.isContentEditable }
            : null,
      });
      if (action === undefined) {
        return;
      }
      switch (action) {
        case "focus-search":
          e.preventDefault();
          setSection("items");
          setSidebarOpen(false);
          // The search input lives in `ItemsPane`, which only mounts for `section === "items"`;
          // the focus is queued for the frame after that state change lands.
          requestAnimationFrame(() => {
            document.querySelector<HTMLInputElement>(".item-list-toolbar input[type='search']")?.focus();
          });
          break;
        case "new-item":
          if (section === "items" && !session.readOnly) {
            e.preventDefault();
            setNewItemSignal((n) => n + 1);
          }
          break;
        case "help":
          e.preventDefault();
          setShortcutsOpen((o) => !o);
          break;
        case "escape":
          if (shortcutsOpen) {
            setShortcutsOpen(false);
          } else if (accountMenuOpen) {
            setAccountMenuOpen(false);
          } else if (sidebarOpen) {
            setSidebarOpen(false);
          }
          break;
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [section, session.readOnly, shortcutsOpen, accountMenuOpen, sidebarOpen]);

  const ctx: VaultContext = { client, clipboard, session, afterWrite: sync, revision, generator };

  /** Chooses an item filter and switches to the item list. */
  const chooseScope = (next: Scope) => {
    setScope(next);
    setSection("items");
    setSidebarOpen(false);
  };

  const chooseSection = (next: Section) => {
    setSection(next);
    setSidebarOpen(false);
  };

  return (
    <div className={sidebarOpen ? "shell sidebar-open" : "shell"}>
      <button
        type="button"
        className="secondary menu-toggle"
        aria-label={sidebarOpen ? "Close menu" : "Open menu"}
        aria-expanded={sidebarOpen}
        onClick={() => setSidebarOpen((v) => !v)}
      >
        <IconMenu />
      </button>
      {sidebarOpen && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close menu"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <nav className="sidebar" aria-label="Vault navigation">
        <div className="sidebar-brand">
          <strong>rizzy-vault</strong> <span className="muted">{props.loginName}</span>
        </div>
        <div className="sidebar-group">
          {ITEM_FILTERS.map((f) => (
            <button
              key={f.label}
              type="button"
              className={
                section === "items" && scopeEquals(scope, f.scope) ? "sidebar-item active" : "sidebar-item"
              }
              aria-current={section === "items" && scopeEquals(scope, f.scope) ? "page" : undefined}
              onClick={() => chooseScope(f.scope)}
            >
              {f.icon === "all" ? <IconAllItems /> : f.icon === "favorites" ? <IconStarFilled /> : <TypeIcon type={f.icon} />}
              {f.label}
            </button>
          ))}
          <button
            type="button"
            className={section === "trash" ? "sidebar-item active" : "sidebar-item"}
            aria-current={section === "trash" ? "page" : undefined}
            onClick={() => chooseSection("trash")}
          >
            <IconTrash /> Trash
          </button>
        </div>
        {tags.length > 0 && (
          <div className="sidebar-group" aria-label="Tags">
            <div className="sidebar-group-label">Tags</div>
            {tags.map(({ tag, count }) => {
              const tagScope: Scope = { kind: "tag", tag };
              const active = section === "items" && scopeEquals(scope, tagScope);
              return (
                <button
                  key={tag}
                  type="button"
                  className={active ? "sidebar-item active" : "sidebar-item"}
                  aria-current={active ? "page" : undefined}
                  onClick={() => chooseScope(tagScope)}
                >
                  <IconTag /> {tag} <span className="muted sidebar-item-count">{count}</span>
                </button>
              );
            })}
          </div>
        )}
        <div className="sidebar-group">
          {OTHER_SECTIONS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={s.id === section ? "sidebar-item active" : "sidebar-item"}
              aria-current={s.id === section ? "page" : undefined}
              onClick={() => chooseSection(s.id)}
            >
              {s.icon} {s.label}
            </button>
          ))}
          <button
            type="button"
            className={section === "settings" ? "sidebar-item active" : "sidebar-item"}
            aria-current={section === "settings" ? "page" : undefined}
            onClick={() => chooseSection("settings")}
          >
            <IconSettings /> Settings
          </button>
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <div className="sync-state" aria-live="polite">
            {syncing
              ? "Syncing…"
              : session.unsentChanges > 0
                ? `${session.unsentChanges} change(s) not synced`
                : "Synced"}
            {session.readOnly && <span className="badge">read-only</span>}
          </div>
          <div className="actions">
            <button type="button" className="secondary" onClick={() => void sync()} disabled={syncing}>
              Sync
            </button>
            <span className="menu-anchor account-menu" ref={accountMenuAnchorRef}>
              <button
                type="button"
                ref={accountMenuTriggerRef}
                className="secondary icon-button"
                aria-label="Account menu"
                aria-expanded={accountMenuOpen}
                aria-haspopup="menu"
                onClick={() => setAccountMenuOpen((o) => !o)}
              >
                <IconAccount /> <IconChevronDown />
              </button>
              {accountMenuOpen && (
                <div className="dropdown-menu" role="menu" aria-label="Account">
                  <button
                    type="button"
                    role="menuitem"
                    className="row"
                    onClick={() => {
                      setAccountMenuOpen(false);
                      chooseSection("settings");
                    }}
                  >
                    <IconSettings /> Settings
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    className="row"
                    onClick={() => {
                      setAccountMenuOpen(false);
                      lockNow();
                    }}
                  >
                    <IconLock /> Lock
                  </button>
                </div>
              )}
            </span>
          </div>
        </header>
        <ErrorText code={syncError} />
        <section className="vault-body">
          {section === "items" && (
            <ItemsPane ctx={ctx} trash={false} scope={scope} newItemSignal={newItemSignal} />
          )}
          {section === "trash" && <ItemsPane ctx={ctx} trash scope={ALL_SCOPE} newItemSignal={0} />}
          {section === "generator" && <GeneratorPane ctx={ctx} />}
          {section === "transfer" && <TransferPane ctx={ctx} />}
          {section === "settings" && <SettingsView ctx={ctx} />}
        </section>
      </div>
      <ConfirmDialog
        open={confirmLock}
        titleId="confirm-lock-title"
        title="Lock with unsaved changes?"
        description={`${session.unsentChanges} change(s) are not on the server yet and will be lost.`}
        confirmLabel="Lock anyway"
        danger
        onConfirm={() => {
          setConfirmLock(false);
          lock();
        }}
        onCancel={() => setConfirmLock(false)}
      />
      <ShortcutsHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

/** Whether two item-list scopes are the same filter (module docs above `Scope`). */
function scopeEquals(a: Scope, b: Scope): boolean {
  if (a.kind !== b.kind) {
    return false;
  }
  if (a.kind === "type" && b.kind === "type") {
    return a.itemType === b.itemType;
  }
  if (a.kind === "tag" && b.kind === "tag") {
    return a.tag === b.tag;
  }
  return true;
}
