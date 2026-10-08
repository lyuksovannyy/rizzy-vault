// The handoff contract for the `rizzy-wasm` bindings this extension needs and does not yet
// have. `crates/rizzy-wasm` today exports the web vault's ephemeral flow (`LoginFlow`,
// `Session`, CRYPTO.md §11.4) and nothing of `rizzy_client::device` (durable-device enrolment
// §11.2, unlock §11.3) or `rizzy_client::store` (the changeset/row model ADR 0026 §3 needs for
// an IndexedDB adapter). ADR 0036 assumes both exist ("the extension reuses `rizzy-wasm`... no
// new persistent format"); this file is the exact TypeScript surface the rest of
// `apps/extension` is written against, so wiring in the real bindings is a mechanical swap of
// this file's bodies, not a redesign of anything that calls it.
//
// Why this was not attempted in the same change: `rizzy-client`'s reference port of this logic
// (`rv`, M1) is `crates/rizzy-cli/src/enrol.rs` + `device.rs` + `db.rs`, together ~3,700 lines
// implementing CRYPTO.md §11.2/§11.3 end to end against `rizzy_client::device`/`login`/`store`.
// Porting that to wasm bindings correctly, with the crypto-custody review CLAUDE.md's ADR gate
// and "a mistake here leaks people's passwords" demand, is its own bounded task, not a few
// hours inside a larger one. Every function below throws {@link BINDINGS_NOT_IMPLEMENTED}
// instead of returning a value that could look like it worked.
//
// What the eventual implementation adds, concretely:
// - `crates/rizzy-wasm/src/device.rs`: wraps `rizzy_client::device::DeviceState` (parse,
//   `unlock(password)` → `UnlockedDevice`, CRYPTO.md §11.3) and the new-device enrolment steps
//   of §11.2 (mirroring `rv`'s `enrol.rs`), exported with `#[wasm_bindgen]` the way
//   `crates/rizzy-wasm/src/login.rs` wraps the ephemeral flow today.
// - `crates/rizzy-wasm/src/store.rs`: exposes `rizzy_client::store`'s record codec and
//   `Changeset` application (ADR 0026 §4's write-order rules) as plain byte-in/byte-out calls,
//   so `cache/idb.ts` can stay "moves bytes only, parses nothing" (ADR 0036 §6).
// - Regenerating `packages/core/generated/rizzy_core.*` and, if `crates/rizzy-wasm` sources
//   changed structurally, the wasm-bindgen expansion baseline
//   (`RUSTC_BOOTSTRAP=1 CARGO_PROFILE_DEV_DEBUG=0 cargo xtask expand-bindings --write`).

/** The one error every unimplemented binding throws, so a caller can tell "not wired yet" apart
 * from any real `CoreError` code without parsing a message string. */
export const BINDINGS_NOT_IMPLEMENTED = "bindings_not_implemented";

export class BindingsNotImplemented extends Error {
  readonly code = BINDINGS_NOT_IMPLEMENTED;
  constructor(symbol: string) {
    super(`${symbol}: rizzy-wasm has no durable-device/store bindings yet (see core/bindings.ts)`);
    this.name = "BindingsNotImplemented";
  }
}

/** Wraps `rizzy_client::login`'s new-device path + `rizzy_client::device::DeviceState`'s
 * construction (CRYPTO.md §11.2 "login on a new device, server mode"): server origin, login
 * name, Secret Key and master password in; a device-state record (ADR 0026 §2) and a
 * `DeviceSession` (`rizzy-client/src/session.rs`) out. `device_kind` is fixed at 2 (ADR 0036
 * §1) by the implementation, not passed in. */
export function enrolDevice(input: {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: string;
  readonly masterPassword: string;
}): never {
  void input;
  throw new BindingsNotImplemented("rizzy_client::login::start_login + device::DeviceState (§11.2)");
}

/** Wraps `DeviceState::unlock` (CRYPTO.md §11.3 offline part: one Argon2id run against
 * `E_local`) followed by the online device-authentication part (§5.10) that
 * `rizzy_client::session::device_auth_start`/`finish` already implement. `deviceStateRecord` is
 * the opaque bytes `cache/idb.ts` reads back from the `device_state` store. */
export function unlockDevice(input: {
  readonly deviceStateRecord: Uint8Array;
  readonly masterPassword: string;
}): never {
  void input;
  throw new BindingsNotImplemented("rizzy_client::device::DeviceState::unlock (§11.3)");
}

/** Zeroizes every handle the long-lived context holds for the current unlock (ADR 0013 §3 rule
 * 1). Safe to call when nothing is unlocked. */
export function lockDevice(): void {
  // No handles exist yet (nothing above ever returns an unlocked value), so there is nothing
  // to zeroize. This function is real (not a throw) so `core-context.ts` can call it
  // unconditionally from both the explicit-lock and auto-lock paths today, before any binding
  // exists, without a special case that would have to be found and removed later.
}

/** Wraps the generator bindings `rizzy-wasm/src/generator.rs` already exports (these exist
 * today; listed here only so `core-context.ts` has one import surface for "the core"). Left
 * unimplemented in this stub module on purpose: `apps/extension` should import
 * `@rizzy-vault/core`'s existing `generatePasswordWithOptions`/`generatePassphraseWithOptions`
 * directly for this one case, the same way `apps/web` does, rather than re-wrapping a binding
 * that is not missing. */
export function generatorIsAlreadyAvailable(): true {
  return true;
}

/** Wraps `rizzy_client::store`'s changeset application for one IndexedDB write batch (ADR 0026
 * §4's write-order rules: never move a monotonic column backwards). `storeName` and `key` are
 * exactly `cache/stores.ts`'s constants; this call parses `recordBytes`, checks the invariants,
 * and returns the exact `(storeName, key, bytes)` triples to write — `cache/idb.ts` never
 * decides this itself (ADR 0036 §6: the adapter "parses nothing"). */
export function applyChangeset(recordBytes: Uint8Array): never {
  void recordBytes;
  throw new BindingsNotImplemented("rizzy_client::store::Changeset application (ADR 0026 §4)");
}
