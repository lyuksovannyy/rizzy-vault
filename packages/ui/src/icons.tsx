// Inline SVG icon components for the web vault (ADR 0014 §2: static markup only, no icon
// font, no third-party origin). Every icon is `aria-hidden` and carries no text of its own: the
// visible label beside it (a button's own accessible name) is what screen readers announce, so
// swapping or removing an icon never changes a control's name or role.
import type { ReactNode } from "react";

/** Shared props of every icon below. */
interface IconProps {
  readonly className?: string | undefined;
}

/** The item types a type icon is drawn for, matching `@rizzy-vault/core`'s `ItemType` literal
 * for literal (not `import type`) because `packages/ui` has no dependency on `packages/core`
 * (ADR 0014 §5: the design system is shared by every surface, core-agnostic); a caller passing
 * an `ItemType | "unknown"` value still type-checks structurally against this same literal set. */
export type IconItemType =
  | "login"
  | "note"
  | "card"
  | "identity"
  | "ssh-key"
  | "api-credential"
  | "software-license"
  | "wifi"
  | "bank-account"
  | "passkey";

function base(children: ReactNode, props: IconProps) {
  return (
    <svg
      className={props.className}
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

/** A login item (key). */
export function IconLogin(props: IconProps) {
  return base(
    <>
      <circle cx="8" cy="8" r="4" />
      <path d="M11 11 20 20M15 16l3 3M18 13l3 3" />
    </>,
    props,
  );
}

/** A secure note. */
export function IconNote(props: IconProps) {
  return base(
    <>
      <path d="M6 3h9l3 3v15H6z" />
      <path d="M15 3v3h3" />
      <path d="M9 11h6M9 15h6" />
    </>,
    props,
  );
}

/** A payment card. */
export function IconCard(props: IconProps) {
  return base(
    <>
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M3 10h18" />
      <path d="M7 14h4" />
    </>,
    props,
  );
}

/** An identity. */
export function IconIdentity(props: IconProps) {
  return base(
    <>
      <circle cx="12" cy="8" r="3.2" />
      <path d="M5 20c0-3.6 3.2-6 7-6s7 2.4 7 6" />
    </>,
    props,
  );
}

/** An unrecognised item type. */
export function IconUnknown(props: IconProps) {
  return base(
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 16v.01M12 8.5c1.4 0 2.5.9 2.5 2s-1.1 1.8-1.7 2.3c-.4.4-.8.8-.8 1.2" />
    </>,
    props,
  );
}

/** The icon for an item's type; falls back to {@link IconUnknown}. */
export function TypeIcon(props: IconProps & { readonly type: IconItemType | "unknown" }) {
  switch (props.type) {
    case "login":
      return <IconLogin className={props.className} />;
    case "note":
      return <IconNote className={props.className} />;
    case "card":
      return <IconCard className={props.className} />;
    case "identity":
      return <IconIdentity className={props.className} />;
    default:
      return <IconUnknown className={props.className} />;
  }
}

/** A filled star (favorite). */
export function IconStarFilled(props: IconProps) {
  return (
    <svg
      className={props.className}
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6L12 17.4l-5.9 3.2 1.3-6.6-4.9-4.6 6.6-.8z" />
    </svg>
  );
}

/** An outline star (not a favorite). */
export function IconStarOutline(props: IconProps) {
  return base(<path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6L12 17.4l-5.9 3.2 1.3-6.6-4.9-4.6 6.6-.8z" />, props);
}

/** A magnifying glass (search). */
export function IconSearch(props: IconProps) {
  return base(
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>,
    props,
  );
}

/** A closed padlock (lock the vault). */
export function IconLock(props: IconProps) {
  return base(
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </>,
    props,
  );
}

/** A trash can. */
export function IconTrash(props: IconProps) {
  return base(
    <>
      <path d="M4 7h16" />
      <path d="M9 7V4h6v3" />
      <path d="M6 7l1 14h10l1-14" />
      <path d="M10 11v6M14 11v6" />
    </>,
    props,
  );
}

/** A generated-password die / shuffle. */
export function IconGenerator(props: IconProps) {
  return base(
    <>
      <rect x="4" y="4" width="16" height="16" rx="3" />
      <circle cx="9" cy="9" r="0.6" fill="currentColor" />
      <circle cx="15" cy="9" r="0.6" fill="currentColor" />
      <circle cx="9" cy="15" r="0.6" fill="currentColor" />
      <circle cx="15" cy="15" r="0.6" fill="currentColor" />
      <circle cx="12" cy="12" r="0.6" fill="currentColor" />
    </>,
    props,
  );
}

/** Import/export (two arrows). */
export function IconTransfer(props: IconProps) {
  return base(
    <>
      <path d="M7 7h10M7 7l3-3M7 7l3 3" />
      <path d="M17 17H7M17 17l-3 3M17 17l-3-3" />
    </>,
    props,
  );
}

/** A device (phone/computer). */
export function IconDevices(props: IconProps) {
  return base(
    <>
      <rect x="3" y="5" width="13" height="9" rx="1" />
      <path d="M8 18h5" />
      <rect x="17" y="9" width="4" height="7" rx="1" />
    </>,
    props,
  );
}

/** A shield (two-factor / security). */
export function IconShield(props: IconProps) {
  return base(<path d="M12 3l7 3v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z" />, props);
}

/** All items in the sidebar. */
export function IconAllItems(props: IconProps) {
  return base(
    <>
      <rect x="4" y="4" width="7" height="7" rx="1" />
      <rect x="13" y="4" width="7" height="7" rx="1" />
      <rect x="4" y="13" width="7" height="7" rx="1" />
      <rect x="13" y="13" width="7" height="7" rx="1" />
    </>,
    props,
  );
}

/** Opens a link in a new tab, next to a SafeLink. */
export function IconOpen(props: IconProps) {
  return base(
    <>
      <path d="M9 6H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" />
      <path d="M14 4h6v6M20 4 11 13" />
    </>,
    props,
  );
}

/** The collapsed-sidebar / open-menu hamburger. */
export function IconMenu(props: IconProps) {
  return base(<path d="M4 6h16M4 12h16M4 18h16" />, props);
}
