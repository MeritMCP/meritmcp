import { describe, it, expect } from "vitest";
import { assertCall, assertCatalog } from "../src/functional/asserts.js";

describe("functional assertions", () => {
  it("passes content_contains + structured json_schema when matched", () => {
    const fails = assertCall(
      { not_error: true, content_contains: "5", structured: { json_schema: { type: "object", required: ["sum"], properties: { sum: { const: 5 } } } } },
      { text: "5", isError: false, structured: { sum: 5 } },
    );
    expect(fails).toEqual([]);
  });

  it("fails content_contains on a mismatch", () => {
    expect(assertCall({ content_contains: "5" }, { text: "6", isError: false })).toHaveLength(1);
  });

  it("fails structured json_schema on the wrong value", () => {
    const fails = assertCall(
      { structured: { json_schema: { type: "object", properties: { sum: { const: 5 } } } } },
      { text: "6", isError: false, structured: { sum: 6 } },
    );
    expect(fails).toHaveLength(1);
  });

  it("not_error catches a tool error", () => {
    expect(assertCall({ not_error: true }, { text: "boom", isError: true })).toHaveLength(1);
  });

  it("contains_tools reports the missing tool", () => {
    expect(assertCatalog({ contains_tools: ["a", "b"] }, { toolNames: ["a"] })).toHaveLength(1);
    expect(assertCatalog({ contains_tools: ["a"] }, { toolNames: ["a", "b"] })).toEqual([]);
  });
});
