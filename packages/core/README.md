# @rizzy-vault/core

The only way UI code reaches the Rust core ([ADR 0013](../../docs/adr/0013-shared-client-core.md) §4, [ADR 0014](../../docs/adr/0014-ui-stack.md) §4): a typed TypeScript wrapper over the wasm-bindgen bindings of [`crates/rizzy-wasm`](../../crates/rizzy-wasm/src/lib.rs). The generated files in `generated/` are not exported; import `@rizzy-vault/core` only.

The core is sans-I/O: Rust builds every request and verifies every answer, and `fetchTransport` only carries bytes. In the web vault the module runs in one dedicated Worker, which holds the only wasm instance with keys.

Secrets the user types (master password, Secret Key, export password) are passed as `SecretInput`: a `Uint8Array` is zeroed when the call returns, whatever its outcome, and a string is encoded into an array that is zeroed (the string itself cannot be wiped). The Emergency Kit returns the Secret Key and recovery code as `Uint8Array`, to zero after rendering. When the transport throws during `sync()`, the sync is aborted in the core and the unsent changes stay queued for the next `sync()`.

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
