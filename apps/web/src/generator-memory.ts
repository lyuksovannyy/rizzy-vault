// Session-only generator memory (ROADMAP §4.2 "generate"): the password/passphrase options the
// generator page and the editor's generate popover both start from, and a short history of
// values the generator page produced.
//
// All of it lives only in this hook's React state. `VaultView` (its module docs) calls this
// hook once and holds it for as long as the vault is unlocked: `App.tsx` unmounts `VaultView`
// entirely on lock, which throws this state away with it, so there is nothing to clear by hand
// and nothing that could leak past a lock. None of it is written to storage, sent to the
// server, or kept once the tab is reloaded.
//
// The generator page and the editor's popover share one set of "last used" options rather than
// each keeping their own: a length or character set picked in one place is almost always what
// the user wants in the other, and keeping two independent copies would make "remembered for
// the session" ambiguous about which session it means.
//
// Whether these options could instead live encrypted in the vault (so they also survive a
// reload or follow the account to another device) is a product question for the owner, not an
// engineering default: options are not secrets, but turning them into vault data needs a new
// persisted item shape, which ADR 0013 §3 and the ADR gate (CLAUDE.md) both reserve for an
// Accepted ADR. This module stays in-memory until that ADR exists.
import type { Generated, PassphraseOptions, PasswordOptions } from "@rizzy-vault/core";
import { useCallback, useState } from "react";

import { DEFAULT_PASSPHRASE_OPTIONS, DEFAULT_PASSWORD_OPTIONS } from "./generator-constants.ts";

/** How many of the generator page's values its history keeps, oldest dropped first. */
export const GENERATOR_HISTORY_LIMIT = 5;

/** Which of the generator's two tabs is open. */
export type GeneratorMode = "password" | "passphrase";

/** The generator state a view reads and writes through {@link useGeneratorMemory}. */
export interface GeneratorMemory {
  readonly mode: GeneratorMode;
  readonly setMode: (mode: GeneratorMode) => void;
  readonly passwordOptions: PasswordOptions;
  readonly setPasswordOptions: (options: PasswordOptions) => void;
  readonly passphraseOptions: PassphraseOptions;
  readonly setPassphraseOptions: (options: PassphraseOptions) => void;
  /** The generator page's last few values, newest first. Not used by the editor popover. */
  readonly history: readonly Generated[];
  readonly pushHistory: (value: Generated) => void;
}

/** A fresh generator memory, starting from the core's own defaults (module docs). */
export function useGeneratorMemory(): GeneratorMemory {
  const [mode, setMode] = useState<GeneratorMode>("password");
  const [passwordOptions, setPasswordOptions] = useState<PasswordOptions>(DEFAULT_PASSWORD_OPTIONS);
  const [passphraseOptions, setPassphraseOptions] = useState<PassphraseOptions>(
    DEFAULT_PASSPHRASE_OPTIONS,
  );
  const [history, setHistory] = useState<readonly Generated[]>([]);
  const pushHistory = useCallback((value: Generated) => {
    setHistory((h) => [value, ...h].slice(0, GENERATOR_HISTORY_LIMIT));
  }, []);
  return {
    mode,
    setMode,
    passwordOptions,
    setPasswordOptions,
    passphraseOptions,
    setPassphraseOptions,
    history,
    pushHistory,
  };
}
