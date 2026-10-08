// A tiny in-memory stand-in for the browser's IndexedDB, written for `test/idb.test.ts` only.
// It implements exactly the slice of the real API `cache/idb.ts` calls: `factory.open` /
// `deleteDatabase`, the `upgradeneeded` / `success` / `error` request events, `db.createObjectStore`,
// `db.objectStoreNames.contains`, `db.transaction(...).objectStore(...).get/put/delete/openCursor`,
// and cursor `.continue()`. It is not a general IndexedDB implementation (no indexes, no key
// ranges, no real `versionchange`): `fake-indexeddb` is not a dependency of this workspace
// (`apps/extension/package.json`), and adding one only for this one test file would be an
// unjustified new dependency (CLAUDE.md "Dependencies"), so this fake is small and scoped to
// exactly `cache/idb.ts`'s own needs instead.
//
// Vitest's `environment: "node"` (`vite.config.ts`) has no global `indexedDB`, so every test
// using this fake passes it explicitly as `ExtensionCache.open`'s `factory` argument — the real
// adapter never reaches for `globalThis.indexedDB` itself except as that argument's default.

type Listener = () => void;

class FakeRequest<T> {
  result: T | undefined;
  error: unknown;
  readonly #listeners = new Map<string, Listener[]>();

  addEventListener(type: string, cb: Listener): void {
    const list = this.#listeners.get(type) ?? [];
    list.push(cb);
    this.#listeners.set(type, list);
  }

  dispatch(type: string): void {
    for (const cb of this.#listeners.get(type) ?? []) {
      cb();
    }
  }

  succeed(result: T): void {
    this.result = result;
    queueMicrotask(() => this.dispatch("success"));
  }

  fail(error: unknown): void {
    this.error = error;
    queueMicrotask(() => this.dispatch("error"));
  }
}

function runRequest<T>(fn: () => T): FakeRequest<T> {
  const req = new FakeRequest<T>();
  try {
    req.succeed(fn());
  } catch (e) {
    req.fail(e);
  }
  return req;
}

function keyOf(key: Uint8Array): string {
  // This fake only ever needs equality lookup (`get`/`put`/`delete` by exact key), never a
  // range query, so a plain string encoding of the bytes is a sufficient map key.
  return Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
}

class FakeCursor {
  constructor(
    readonly key: Uint8Array,
    readonly value: Uint8Array,
    private readonly advance: () => void,
  ) {}

  continue(): void {
    this.advance();
  }
}

function openCursorRequest(entries: ReadonlyArray<readonly [Uint8Array, Uint8Array]>): FakeRequest<FakeCursor | null> {
  const req = new FakeRequest<FakeCursor | null>();
  let i = 0;
  const advance = (): void => {
    if (i >= entries.length) {
      req.succeed(null);
      return;
    }
    const [key, value] = entries[i]!;
    i += 1;
    req.succeed(new FakeCursor(key, value, advance));
  };
  advance();
  return req;
}

class FakeObjectStoreHandle {
  constructor(private readonly table: Map<string, { key: Uint8Array; value: Uint8Array }>) {}

  get(key: Uint8Array): FakeRequest<Uint8Array | undefined> {
    return runRequest(() => this.table.get(keyOf(key))?.value);
  }

  put(value: Uint8Array, key: Uint8Array): FakeRequest<Uint8Array> {
    return runRequest(() => {
      // Defensive copies, matching a real browser's structured clone: mutating the caller's
      // array after `put` must never change what is stored.
      this.table.set(keyOf(key), { key: new Uint8Array(key), value: new Uint8Array(value) });
      return key;
    });
  }

  delete(key: Uint8Array): FakeRequest<undefined> {
    return runRequest(() => {
      this.table.delete(keyOf(key));
      return undefined;
    });
  }

  openCursor(): FakeRequest<FakeCursor | null> {
    const entries = Array.from(this.table.values(), (row) => [row.key, row.value] as const);
    return openCursorRequest(entries);
  }
}

class FakeTransaction {
  constructor(private readonly store: Map<string, { key: Uint8Array; value: Uint8Array }>) {}

  objectStore(): FakeObjectStoreHandle {
    return new FakeObjectStoreHandle(this.store);
  }
}

class FakeDatabase {
  readonly #stores = new Map<string, Map<string, { key: Uint8Array; value: Uint8Array }>>();
  readonly objectStoreNames = { contains: (name: string): boolean => this.#stores.has(name) };

  createObjectStore(name: string): void {
    this.#stores.set(name, new Map());
  }

  transaction(storeName: string): FakeTransaction {
    const table = this.#stores.get(storeName);
    if (table === undefined) {
      throw new Error(`fake-idb: no such object store "${storeName}"`);
    }
    return new FakeTransaction(table);
  }

  close(): void {
    // Nothing to release in-memory.
  }
}

/** The fake `IDBFactory`. One instance per test (or per test file) gives each test its own
 * isolated set of databases, same as a fresh browser profile would. */
export class FakeIndexedDBFactory {
  readonly #databases = new Map<string, FakeDatabase>();

  open(name: string): FakeRequest<FakeDatabase> {
    const req = new FakeRequest<FakeDatabase>();
    queueMicrotask(() => {
      let db = this.#databases.get(name);
      const isNew = db === undefined;
      if (db === undefined) {
        db = new FakeDatabase();
        this.#databases.set(name, db);
      }
      req.result = db;
      if (isNew) {
        req.dispatch("upgradeneeded");
      }
      req.dispatch("success");
    });
    return req;
  }

  deleteDatabase(name: string): FakeRequest<undefined> {
    this.#databases.delete(name);
    return runRequest(() => undefined);
  }
}
