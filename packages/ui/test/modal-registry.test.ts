// `modalRegistry.ts`'s pure open-count tracking (module docs there: `ConfirmDialog` registers
// itself through this so the web vault's global shortcut handler can suppress shortcuts while
// any confirm dialog, anywhere, is open).
import { beforeEach, describe, expect, it } from "vitest";

import { isAnyModalOpen, setModalOpen } from "../src/modalRegistry.ts";

// The registry is one module-level counter; drain it back to zero before each test so one
// test's opens can never leak into the next.
beforeEach(() => {
  while (isAnyModalOpen()) {
    setModalOpen(false);
  }
});

describe("isAnyModalOpen / setModalOpen", () => {
  it("is false with nothing registered", () => {
    expect(isAnyModalOpen()).toBe(false);
  });

  it("is true once one dialog registers open", () => {
    setModalOpen(true);
    expect(isAnyModalOpen()).toBe(true);
  });

  it("stays true while a second, unrelated dialog is also open", () => {
    setModalOpen(true);
    setModalOpen(true);
    expect(isAnyModalOpen()).toBe(true);
    setModalOpen(false);
    expect(isAnyModalOpen()).toBe(true);
    setModalOpen(false);
    expect(isAnyModalOpen()).toBe(false);
  });

  it("never goes negative on an unbalanced close", () => {
    setModalOpen(false);
    setModalOpen(false);
    expect(isAnyModalOpen()).toBe(false);
    setModalOpen(true);
    expect(isAnyModalOpen()).toBe(true);
  });
});
