import { describe, it, expect } from "vitest";
import { isApplicable } from "../src/conformance/wrapper.js";

// isApplicable decides which official-conformance scenarios actually count toward the score.
// Getting this wrong is how a scanner unfairly fails honest servers, so it's worth pinning down.
describe("conformance applicability (capability + transport aware)", () => {
  it("core protocol scenarios always apply", () => {
    expect(isApplicable("server-initialize", { transport: "stdio" })).toBe(true);
    expect(isApplicable("ping", { transport: "stdio" })).toBe(true);
  });

  it("tools scenarios apply only when the server declares the tools capability", () => {
    for (const s of ["tools-list", "tools-call-simple-text", "tools-call-error"]) {
      expect(isApplicable(s, { transport: "stdio", capabilities: { tools: {} } })).toBe(true);
      expect(isApplicable(s, { transport: "stdio", capabilities: {} })).toBe(false);
    }
  });

  it("resources/prompts/logging are each gated on their own capability", () => {
    expect(isApplicable("resources-list", { transport: "stdio", capabilities: { resources: {} } })).toBe(true);
    expect(isApplicable("resources-list", { transport: "stdio", capabilities: { prompts: {} } })).toBe(false);
    expect(isApplicable("prompts-list", { transport: "stdio", capabilities: { prompts: {} } })).toBe(true);
    expect(isApplicable("logging-set-level", { transport: "stdio", capabilities: { logging: {} } })).toBe(true);
    expect(isApplicable("logging-set-level", { transport: "stdio", capabilities: {} })).toBe(false);
  });

  it("excludes named-fixture scenarios that only the SDK reference server can satisfy", () => {
    const allCaps = { capabilities: { tools: {}, resources: {}, prompts: {}, logging: {} }, transport: "stdio" as const };
    for (const s of ["prompts-get-simple", "resources-read-text", "completion-complete", "tools-call-image"]) {
      expect(isApplicable(s, allCaps)).toBe(false);
    }
  });

  it("HTTP-transport scenarios apply over real http but never over the stdio proxy", () => {
    expect(isApplicable("dns-rebinding-protection", { transport: "http" })).toBe(true);
    expect(isApplicable("dns-rebinding-protection", { transport: "stdio" })).toBe(false);
    expect(isApplicable("server-sse-multiple-streams", { transport: "http" })).toBe(true);
    expect(isApplicable("server-sse-multiple-streams", { transport: "stdio" })).toBe(false);
  });
});
