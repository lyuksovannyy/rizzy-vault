// SPDX-License-Identifier: AGPL-3.0-only

// Session-only identity generator memory (ADR 0079 §3 "The default": "18–27 the first time;
// after that the last-used range"): the age range the last saved generated identity used.
//
// Like `generator-memory.ts`, it lives only in this hook's React state, which `VaultView` holds
// while the vault is unlocked and drops on lock; nothing is stored or sent. It is not synced on
// every create because writing the synced defaults (ACCOUNT_SETTINGS tag 0x0004, ADR 0079 Open
// question 7) is an `account/commit`, which the server takes only within five minutes of a login
// (`server_fresh_session_required`): a create must never fail or nag for that. The synced range
// is written only from Settings → Identity generator (`IdentityDefaultsPane.tsx`), which also
// clears this memory so the saved range applies to the next identity.
import { useState } from "react";

import type { AgeRange } from "./identity-form.ts";

/** The identity generator's in-memory, session-only state (module docs). */
export interface IdentityMemory {
  /** The last-used age range of this session, over the synced default; `undefined` if none. */
  readonly lastAge: AgeRange | undefined;
  readonly setLastAge: (range: AgeRange | undefined) => void;
}

/** Holds {@link IdentityMemory} for one unlocked session (module docs). */
export function useIdentityMemory(): IdentityMemory {
  const [lastAge, setLastAge] = useState<AgeRange | undefined>();
  return { lastAge, setLastAge };
}
