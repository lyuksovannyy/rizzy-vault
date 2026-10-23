// SPDX-License-Identifier: AGPL-3.0-only

// An item's icon: the site's icon from the server's `icons` role when there is one
// (`itemIcons.ts`), the item-type icon otherwise. Decorative either way: the row or header
// next to it names the item, so the image has an empty `alt` and the type icon is hidden from
// assistive technology.
import { useEffect, useSyncExternalStore } from "react";

import { type IconItemType, TypeIcon } from "./icons.tsx";
import type { IconLoader } from "./itemIcons.ts";

/** The site icon's URL for `websiteHost`, or `null`; starts its fetch once. */
export function useItemIcon(icons: IconLoader | undefined, websiteHost: string | undefined): string | null {
  useEffect(() => {
    if (icons !== undefined && websiteHost !== undefined) {
      icons.request(websiteHost);
    }
  }, [icons, websiteHost]);
  return useSyncExternalStore(
    (listener) => icons?.subscribe(listener) ?? (() => undefined),
    () => (icons === undefined || websiteHost === undefined ? null : icons.peek(websiteHost)),
  );
}

/** The icon of one item (module docs). `size` is the image's CSS pixel size. */
export function ItemIcon(props: {
  readonly icons: IconLoader | undefined;
  readonly websiteHost: string | undefined;
  readonly itemType: IconItemType | "unknown";
  readonly size: number;
}) {
  const url = useItemIcon(props.icons, props.websiteHost);
  if (url === null) {
    return <TypeIcon type={props.itemType} />;
  }
  return (
    <img
      className="item-favicon"
      src={url}
      alt=""
      width={props.size}
      height={props.size}
      decoding="async"
      draggable={false}
    />
  );
}
