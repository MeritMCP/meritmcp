import { describe, it, expect } from "vitest";
import { scanSecrets } from "../src/security/static/secrets.js";
import { scanUnicode } from "../src/security/static/unicode.js";

describe("secrets (MCP01)", () => {
  it("flags a structured key with high confidence and redacts it", () => {
    const f = scanSecrets([{ label: "d", text: "auth token sk-live-9f8a7b6c5d4e3f2a1b0c here", location: "x" }]);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe("high");
    expect(f[0].ruleId).toBe("MCP01-secret");
    expect(f[0].message).not.toContain("9f8a7b6c5d4e3f2a1b0c"); // redacted
  });

  it("flags an AWS access key id", () => {
    const f = scanSecrets([{ label: "d", text: "AKIAIOSFODNN7EXAMPLE", location: "x" }]);
    expect(f).toHaveLength(1);
  });

  it("does not flag ordinary prose (anti-FP)", () => {
    const f = scanSecrets([{ label: "d", text: "This tool adds two numbers and returns the sum.", location: "x" }]);
    expect(f).toHaveLength(0);
  });
});

describe("unicode poisoning (MCP03a)", () => {
  it("detects zero-width space and bidi override", () => {
    const text = "hello​world‮"; // U+200B zero-width space, U+202E RTL override
    const f = scanUnicode([{ label: "d", text, location: "x" }]);
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.confidence === "high")).toBe(true);
  });

  it("clean text produces no findings", () => {
    expect(scanUnicode([{ label: "d", text: "a normal tool description", location: "x" }])).toHaveLength(0);
  });
});
