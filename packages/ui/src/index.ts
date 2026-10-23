// SPDX-License-Identifier: AGPL-3.0-only

// @rizzy-vault/ui — the web design system (ADR 0014 §5), minimal in M1. The token CSS is
// imported by path (`@rizzy-vault/ui/tokens.css`).
export { PasswordGenerateSlot } from "./PasswordGenerateSlot.tsx";
export { SecretField, SECRET_INPUT_ATTRIBUTES, type SecretFieldProps } from "./SecretField.tsx";
export {
  IconAccount,
  IconAllItems,
  IconApiCredential,
  IconBack,
  IconBankAccount,
  IconCard,
  IconChevronDown,
  IconClose,
  IconDevices,
  IconGenerator,
  IconIdentity,
  IconLock,
  IconLogin,
  IconMenu,
  IconNote,
  IconOpen,
  IconPlus,
  IconSearch,
  IconSettings,
  IconShield,
  IconSoftwareLicense,
  IconSshKey,
  IconStarFilled,
  IconStarOutline,
  IconTag,
  IconTransfer,
  IconTrash,
  IconUnknown,
  IconWifi,
  TypeIcon,
} from "./icons.tsx";
export { ConfirmDialog, type ConfirmDialogProps } from "./ConfirmDialog.tsx";
export { ItemIcon, useItemIcon } from "./ItemIcon.tsx";
export {
  type IconFetcher,
  IconLoader,
  type IconTimers,
  type IconUrls,
  MAX_CONCURRENT as ICON_MAX_CONCURRENT,
  RATE_LIMIT_WAIT_MS as ICON_RATE_LIMIT_WAIT_MS,
  blobUrls,
  iconKey,
} from "./itemIcons.ts";
export { nextFocusIndex, trapTab } from "./focusTrap.ts";
export { isAnyModalOpen, setModalOpen } from "./modalRegistry.ts";
export {
  TOAST_DURATION_MS,
  ToastProvider,
  type ToastItem,
  type ToastKind,
  toastReducer,
  useToast,
} from "./Toast.tsx";
