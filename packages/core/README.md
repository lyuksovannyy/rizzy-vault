# @rizzy-vault/core

The only way UI code reaches the Rust core ([ADR 0013](../../docs/adr/0013-shared-client-core.md) §4, [ADR 0014](../../docs/adr/0014-ui-stack.md) §4): a typed TypeScript wrapper over the wasm-bindgen bindings of [`crates/rizzy-wasm`](../../crates/rizzy-wasm/src/lib.rs). The generated files in `generated/` are not exported; import `@rizzy-vault/core` only.

The core is sans-I/O: Rust builds every request and verifies every answer, and `fetchTransport` only carries bytes. In the web vault the module runs in one dedicated Worker, which holds the only wasm instance with keys.

Secrets the user types (master password, Secret Key, export password) are passed as `SecretInput`: a `Uint8Array` is zeroed when the call returns, whatever its outcome, and a string is encoded into an array that is zeroed (the string itself cannot be wiped). The Emergency Kit returns the Secret Key and recovery code as `Uint8Array`, to zero after rendering. When the transport throws during `sync()`, the sync is aborted in the core and the unsent changes stay queued for the next `sync()`.

Every export needs `reauthenticate()` first (the Secret Key and master password typed again), which allows one export within five minutes; otherwise the core throws `reauth_required`. A plaintext export also needs `plaintextWarningShown()` when the warning is on screen and the hold of `plaintextExportHoldMs()` (10 s) to be over, or it throws `plaintext_export_hold`. `detectImportFormat(file)` names an import file's format from its bytes, so the host does not ask for it in the common case (owner decision 2026-10-05).

The generator takes every option of `rizzy-core`'s: `generatePasswordWithOptions(options)` (`length`, a rule of `"excluded" | "included" | "required"` per class, `excludeAmbiguous`, `exclude`, `symbolSet`) and `generatePassphraseWithOptions(options)` (`words`, `separator`, `capitalize`, `includeNumber`), with defaults in `DEFAULT_PASSWORD_OPTIONS` and `DEFAULT_PASSPHRASE_OPTIONS` and bounds in `GENERATOR_LIMITS`. `passwordEntropy` and `passphraseEntropy` give the entropy without generating; `checkPasswordOptions` and `checkPassphraseOptions` return it, or the refusal's `generator_*` code and a sentence from `GENERATOR_ERROR_MESSAGES`, for a live display. There is one generator API, not two: the plain `generatePassword(length, symbols, excludeAmbiguous)` and `generatePassphrase(words)` this module once also exported were removed once the web vault's generator page and editor needed every option anyway — nothing else depended on the plain calls, and keeping two option-passing conventions in a crypto module was worse than the one-line migration (`generatePasswordWithOptions({ length })` for the old default).

## Build and test

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run build:wasm        # cargo xtask build-wasm: rizzy-wasm → packages/core/generated/
pnpm run build             # tsc → packages/core/dist/
cargo build -p rizzy-server --bin rizzy-vault   # for the end-to-end test
pnpm run test              # Vitest: unit tests, and the end-to-end test against rizzy-vault
```

`cargo xtask build-wasm` needs `wasm-bindgen-cli` at exactly the `wasm-bindgen` version in `Cargo.lock` (`cargo install wasm-bindgen-cli --version <it> --locked`); it refuses any other. The end-to-end test starts the built `target/debug/rizzy-vault` (or `RIZZY_VAULT_BIN`) on a loopback port with a temporary database. Without a binary it is skipped, unless `CI` is set: then it fails.
