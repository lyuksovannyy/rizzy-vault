// `ItemEditor`'s pure list-reorder helper: moving a still-unsaved website or custom-field row
// up or down in the pending list before the first save (ItemEditor.tsx module docs).
import { describe, expect, it } from "vitest";

import { moved } from "../src/views/ItemEditor.tsx";

describe("moved", () => {
  it("swaps the element at `index` with its neighbour", () => {
    expect(moved(["a", "b", "c"], 1, -1)).toEqual(["b", "a", "c"]);
    expect(moved(["a", "b", "c"], 1, 1)).toEqual(["a", "c", "b"]);
  });

  it("is a no-op at either end", () => {
    expect(moved(["a", "b", "c"], 0, -1)).toEqual(["a", "b", "c"]);
    expect(moved(["a", "b", "c"], 2, 1)).toEqual(["a", "b", "c"]);
  });

  it("never mutates its input", () => {
    const rows = ["a", "b", "c"];
    moved(rows, 0, 1);
    expect(rows).toEqual(["a", "b", "c"]);
  });

  it("keeps every element exactly once, whatever the move", () => {
    const rows = [1, 2, 3, 4, 5];
    for (let i = 0; i < rows.length; i += 1) {
      for (const dir of [-1, 1] as const) {
        const after = moved(rows, i, dir);
        expect(after).toHaveLength(rows.length);
        expect([...after].sort()).toEqual([...rows].sort());
      }
    }
  });
});
