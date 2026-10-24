// SPDX-License-Identifier: AGPL-3.0-only

// `isOwnOverlayMutation` (`src/content/own-overlay-mutation.ts`): the fix for a real bug found
// only by the E2E suite — the content script's own `MutationObserver` reacting to its own
// inline-menu/save-prompt DOM writes, an unbounded show/hide loop. These tests use plain object
// doubles (duck-typed `hasAttribute`, no real `Node`/`Element`), exactly what the module's own
// doc comment says it was split out to allow under this workspace's `environment: "node"`.
import { describe, expect, it } from "vitest";

import { isOwnOverlayMutation, pageMutations } from "../src/content/own-overlay-mutation.ts";

function fakeNode(attrs: readonly string[]): { hasAttribute: (name: string) => boolean } {
  return { hasAttribute: (name) => attrs.includes(name) };
}

function record(added: readonly string[][], removed: readonly string[][] = []) {
  return { addedNodes: added.map(fakeNode), removedNodes: removed.map(fakeNode) };
}

describe("isOwnOverlayMutation", () => {
  it("is true for an empty batch (vacuously — nothing non-own was touched)", () => {
    expect(isOwnOverlayMutation([])).toBe(true);
  });

  it("is true when every added/removed node is the inline-menu iframe", () => {
    const records = [record([["data-rizzy-inline-menu"]]), record([], [["data-rizzy-inline-menu"]])];
    expect(isOwnOverlayMutation(records)).toBe(true);
  });

  it("is true when every added/removed node is the save-prompt banner", () => {
    const records = [record([["data-rizzy-save-prompt"]])];
    expect(isOwnOverlayMutation(records)).toBe(true);
  });

  it("is false when a batch mixes an own node with a page node", () => {
    const records = [record([["data-rizzy-inline-menu"], []])];
    expect(isOwnOverlayMutation(records)).toBe(false);
  });

  it("is false for a page-only mutation (a real page change must still trigger detection)", () => {
    const records = [record([[]])];
    expect(isOwnOverlayMutation(records)).toBe(false);
  });

  it("is false when one own-only record is followed by a record with a page node", () => {
    const records = [record([["data-rizzy-inline-menu"]]), record([[]])];
    expect(isOwnOverlayMutation(records)).toBe(false);
  });

  it("is false for a node with no hasAttribute at all (a non-Element, e.g. a text node)", () => {
    const records = [{ addedNodes: [{}], removedNodes: [] }];
    expect(isOwnOverlayMutation(records)).toBe(false);
  });
});

// `pageMutations`: the attribute-aware classification the content script's observer uses since
// multi-step login support (a password field revealed in place by an attribute change).
describe("pageMutations", () => {
  function childList(added: readonly string[][], removed: readonly string[][] = []) {
    return { type: "childList", target: fakeNode([]), ...record(added, removed) };
  }
  function attributeChange(target: unknown) {
    return { type: "attributes", target, addedNodes: [], removedNodes: [] };
  }
  const frame = fakeNode(["data-rizzy-inline-menu"]);
  const insideBanner = { ...fakeNode([]), parentNode: { ...fakeNode([]), parentNode: fakeNode(["data-rizzy-save-prompt"]) } };
  const pageElement = { ...fakeNode([]), parentNode: fakeNode([]) };

  it("is none for an empty batch and for our own overlay's own changes", () => {
    expect(pageMutations([])).toBe("none");
    expect(pageMutations([childList([["data-rizzy-inline-menu"]]), attributeChange(frame), attributeChange(insideBanner)])).toBe("none");
  });

  it("is attributes when only attributes changed and one of them on a page element", () => {
    expect(pageMutations([attributeChange(frame), attributeChange(pageElement)])).toBe("attributes");
  });

  it("is structure as soon as a page node was added or removed, whatever else changed", () => {
    expect(pageMutations([attributeChange(pageElement), childList([[]])])).toBe("structure");
    expect(pageMutations([childList([], [[]])])).toBe("structure");
  });

  it("never walks into an own overlay through a page element's parent chain", () => {
    expect(pageMutations([attributeChange({ parentNode: null })])).toBe("attributes");
  });
});
