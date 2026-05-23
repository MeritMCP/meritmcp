import { describe, it, expect } from "vitest";
import { toSarif } from "../src/report/sarif.js";
import { toBadge } from "../src/report/badge.js";
import { toMarkdown, PR_COMMENT_MARKER } from "../src/report/prcomment.js";
import { Report } from "../src/types.js";

const noDrift = { hasSnapshot: false, changed: false, added: [], removed: [], schemaChanged: [], descriptionOnly: [] };

const passReport = (): Report => ({
  verdict: "PASS",
  score: 100,
  capped: false,
  functional: { ran: true, score: 100, passed: 3, total: 3, results: [], drift: noDrift },
  conformance: { ran: true, score: 100, passed: 5, total: 5, rawPassed: 5, rawTotal: 30, scenarios: [] },
  security: { ran: true, score: 100, findings: [] },
  weights: { functional: 0.3, conformance: 0.3, security: 0.4 },
});

const failReport = (): Report => ({
  verdict: "FAIL",
  score: 30,
  capped: true,
  functional: {
    ran: true,
    score: 0,
    passed: 0,
    total: 1,
    results: [{ name: "add(2,2)", passed: false, detail: "expected 4, got 22" }],
    drift: noDrift,
  },
  conformance: { ran: true, score: 100, passed: 5, total: 5, rawPassed: 5, rawTotal: 30, scenarios: [] },
  security: {
    ran: true,
    score: 0,
    findings: [
      {
        ruleId: "MCP05-cmd-injection",
        owasp: "MCP05:2025",
        severity: "critical",
        confidence: "high",
        message: "Tool executed an injected shell command",
        location: "mcp-server://tool/run_command",
      },
    ],
  },
  weights: { functional: 0.3, conformance: 0.3, security: 0.4 },
});

describe("SARIF report", () => {
  it("emits valid SARIF 2.1.0 with the Merit driver + version", () => {
    const s = toSarif(failReport(), "9.9.9") as any;
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0].tool.driver.name).toBe("Merit");
    expect(s.runs[0].tool.driver.version).toBe("9.9.9");
  });

  it("maps a critical security finding to an error result with security-severity + fingerprint", () => {
    const s = toSarif(failReport()) as any;
    const rule = s.runs[0].tool.driver.rules.find((r: any) => r.id === "MCP05-cmd-injection");
    expect(rule.properties["security-severity"]).toBe("9.5");
    expect(rule.defaultConfiguration.level).toBe("error");

    const res = s.runs[0].results.find((r: any) => r.ruleId === "MCP05-cmd-injection");
    expect(res.level).toBe("error");
    expect(res.locations[0].physicalLocation.artifactLocation.uri).toBe("mcp-server://tool/run_command");
    expect(typeof res.partialFingerprints.merit).toBe("string");
  });

  it("surfaces functional failures as their own SARIF rule", () => {
    const s = toSarif(failReport()) as any;
    expect(s.runs[0].results.some((r: any) => r.ruleId === "FUNCTIONAL-test-failed")).toBe(true);
  });

  it("a clean report yields zero results", () => {
    const s = toSarif(passReport()) as any;
    expect(s.runs[0].results).toHaveLength(0);
  });
});

describe("shields badge", () => {
  it("PASS → passing message + brightgreen at 100", () => {
    const b = toBadge(passReport());
    expect(b.label).toBe("Merit");
    expect(b.message).toBe("100/100 · passing");
    expect(b.color).toBe("brightgreen");
  });

  it("FAIL → failing message + red", () => {
    const b = toBadge(failReport());
    expect(b.message).toBe("30/100 · failing");
    expect(b.color).toBe("red");
  });
});

describe("PR comment markdown", () => {
  it("clean run: sticky marker, PASS, no-findings line", () => {
    const md = toMarkdown(passReport());
    expect(md.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(md).toContain("✅ **PASS**");
    expect(md).toContain("✅ no findings");
  });

  it("failing run: shows the cap note, the OWASP id, and the failing functional test", () => {
    const md = toMarkdown(failReport());
    expect(md).toContain("❌ **FAIL**");
    expect(md).toContain("capped");
    expect(md).toContain("MCP05:2025");
    expect(md).toContain("add(2,2)");
  });
});
