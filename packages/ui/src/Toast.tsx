// A small, auto-dismissing notice stack (redesign slice 2, item 1 of the follow-up list):
// success/error/info toasts, each with its own dismiss button, stacked newest-last.
//
// Accessibility: error toasts sit in an `aria-live="assertive"` region (they report a failure
// the user did not expect and should hear about immediately); success/info toasts sit in a
// separate `aria-live="polite"` region, so a success notice never interrupts whatever the
// screen reader is already announcing. Two regions, not one switched dynamically, because an
// `aria-live` region's politeness is read once by most screen readers when the region is first
// discovered — changing it later is unreliable.
//
// State lives in `toastReducer`, a pure function kept separate from the component so it can be
// unit-tested without rendering anything (the project's existing pattern: `ItemsPane.tsx`'s
// `inScope`/`emptyState`). Auto-dismiss timers are the one side effect, run from an effect in
// the provider, never from the reducer itself.
import {
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { IconClose } from "./icons.tsx";

/** A toast's severity, each with its own colour and live-region politeness. */
export type ToastKind = "success" | "error" | "info";

/** One toast on the stack. */
export interface ToastItem {
  readonly id: string;
  readonly kind: ToastKind;
  readonly message: string;
}

/** How long a toast stays up before it auto-dismisses, by kind: errors stay up longer, since
 * they are more likely to need re-reading. */
export const TOAST_DURATION_MS: Readonly<Record<ToastKind, number>> = {
  success: 4000,
  info: 4000,
  error: 7000,
};

type ToastAction =
  | { readonly type: "add"; readonly id: string; readonly kind: ToastKind; readonly message: string }
  | { readonly type: "dismiss"; readonly id: string };

/** The toast stack's pure reducer (module docs): add appends, dismiss removes by id (removing
 * an id already gone is a no-op, not an error — a dismiss can race its own auto-dismiss timer). */
export function toastReducer(state: readonly ToastItem[], action: ToastAction): readonly ToastItem[] {
  switch (action.type) {
    case "add":
      return [...state, { id: action.id, kind: action.kind, message: action.message }];
    case "dismiss":
      return state.filter((t) => t.id !== action.id);
  }
}

interface ToastContextValue {
  readonly notify: (kind: ToastKind, message: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

/** Shows a toast from anywhere under {@link ToastProvider}. Calling it outside one is a bug
 * (every view renders under the one provider near the app root), so it throws rather than
 * silently dropping the notice. */
export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (ctx === undefined) {
    throw new Error("useToast() called outside ToastProvider");
  }
  return ctx;
}

let nextId = 0;
/** A fresh id for a new toast. A module counter, not `crypto.randomUUID()`: toasts need only be
 * unique within this tab's lifetime, and this keeps the id generator synchronous and trivially
 * testable. */
function freshId(): string {
  nextId += 1;
  return `toast-${nextId}`;
}

/** One toast's icon glyph (decorative; the message text alone carries the meaning). */
function kindGlyph(kind: ToastKind): string {
  switch (kind) {
    case "success":
      return "✓";
    case "error":
      return "!";
    case "info":
      return "i";
  }
}

/** One toast, with its own dismiss button. */
function Toast(props: { readonly toast: ToastItem; readonly onDismiss: (id: string) => void }) {
  const { toast } = props;
  return (
    <div className={`toast toast-${toast.kind}`} data-toast-id={toast.id}>
      <span className="toast-icon" aria-hidden="true">
        {kindGlyph(toast.kind)}
      </span>
      <span className="toast-message">{toast.message}</span>
      <button
        type="button"
        className="toast-dismiss icon-button"
        aria-label="Dismiss notification"
        onClick={() => props.onDismiss(toast.id)}
      >
        <IconClose />
      </button>
    </div>
  );
}

/** Wraps the app once near its root. Renders the two live regions (module docs) and provides
 * `useToast` to every descendant. */
export function ToastProvider(props: { readonly children: ReactNode }) {
  const [toasts, setToasts] = useState<readonly ToastItem[]>([]);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: string) => {
    const timer = timers.current.get(id);
    if (timer !== undefined) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
    setToasts((s) => toastReducer(s, { type: "dismiss", id }));
  }, []);

  const notify = useCallback((kind: ToastKind, message: string) => {
    const id = freshId();
    setToasts((s) => toastReducer(s, { type: "add", id, kind, message }));
    const timer = setTimeout(() => {
      timers.current.delete(id);
      setToasts((s) => toastReducer(s, { type: "dismiss", id }));
    }, TOAST_DURATION_MS[kind]);
    timers.current.set(id, timer);
  }, []);

  useEffect(() => {
    const live = timers.current;
    return () => {
      for (const timer of live.values()) {
        clearTimeout(timer);
      }
      live.clear();
    };
  }, []);

  const value = useMemo(() => ({ notify }), [notify]);
  const errors = toasts.filter((t) => t.kind === "error");
  const others = toasts.filter((t) => t.kind !== "error");

  return (
    <ToastContext.Provider value={value}>
      {props.children}
      {/* One positioned wrapper around both live regions (redesign slice 2 follow-up fix): the
          two regions stay separate elements, for the independent aria-live politeness module
          docs above explain, but share this wrapper's flex layout instead of each being fixed
          to the same corner, so a polite and an assertive toast visible at once stack instead
          of overlapping, however many toasts either region holds. */}
      <div className="toast-stack-wrapper">
        <div className="toast-stack" aria-live="polite" aria-label="Notifications">
          {others.map((t) => (
            <Toast key={t.id} toast={t} onDismiss={dismiss} />
          ))}
        </div>
        <div className="toast-stack" aria-live="assertive" aria-label="Error notifications">
          {errors.map((t) => (
            <Toast key={t.id} toast={t} onDismiss={dismiss} />
          ))}
        </div>
      </div>
    </ToastContext.Provider>
  );
}
