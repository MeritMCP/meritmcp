import { describe, it, expect } from "vitest";
import { capture } from "../src/snapshot/capture.js";
import { diff } from "../src/snapshot/diff.js";
import { ToolInfo } from "../src/adapter/mcpClient.js";

const tool = (name: string, description: string, inputSchema: unknown = { type: "object" }): ToolInfo => ({
  name,
  description,
  inputSchema,
});

describe("schema-snapshot drift", () => {
  it("detects added and removed tools", () => {
    const r = diff(capture([tool("x", "d")]), capture([tool("y", "d")]));
    expect(r.added).toEqual(["y"]);
    expect(r.removed).toEqual(["x"]);
    expect(r.changed).toBe(true);
  });

  it("distinguishes a breaking schema change from a description-only rug-pull", () => {
    const base = capture([tool("x", "desc", { type: "object", properties: { a: { type: "string" } } })]);
    const schemaChanged = capture([tool("x", "desc", { type: "object", properties: { a: { type: "number" } } })]);
    const descChanged = capture([tool("x", "DIFFERENT desc", { type: "object", properties: { a: { type: "string" } } })]);

    expect(diff(base, schemaChanged).schemaChanged).toEqual(["x"]);
    expect(diff(base, schemaChanged).descriptionOnly).toEqual([]);
    expect(diff(base, descChanged).descriptionOnly).toEqual(["x"]);
    expect(diff(base, descChanged).schemaChanged).toEqual([]);
  });

  it("reports no drift for an identical surface", () => {
    const a = capture([tool("x", "d", { type: "object" })]);
    const b = capture([tool("x", "d", { type: "object" })]);
    expect(diff(a, b).changed).toBe(false);
  });
});
