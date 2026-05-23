import { describe, it, expect } from "vitest";
import { assemble, securityScore } from "../src/report/score.js";
import { ConformanceOutcome, FunctionalOutcome, Finding } from "../src/types.js";

const conf = (over: Partial<ConformanceOutcome> = {}): ConformanceOutcome => ({
  ran: false,
  score: null,
  passed: 0,
  total: 0,
  rawPassed: 0,
  rawTotal: 0,
  scenarios: [],
  ...over,
});

const func = (over: Partial<FunctionalOutcome> = {}): FunctionalOutcome => ({
  ran: false,
  score: null,
  passed: 0,
  total: 0,
  results: [],
  ...over,
});

describe("scoring", () => {
  it("redistributes weight when only functional ran", () => {
    const r = assemble({
      functional: func({ ran: true, score: 80, passed: 4, total: 5 }),
      conformance: conf(),
      security: { ran: false, score: null, findings: [] },
    });
    expect(r.score).toBe(80); // 0.30 weight renormalised to 1.0
    expect(r.verdict).toBe("FAIL"); // not all functional tests passed
  });

  it("security cap forces FAIL on a high-confidence critical finding", () => {
    const findings: Finding[] = [{ ruleId: "MCP05-cmd-injection", severity: "critical", confidence: "high", message: "x" }];
    const r = assemble({
      functional: func({ ran: true, score: 100, passed: 5, total: 5 }),
      conformance: conf({ ran: true, score: 100 }),
      security: { ran: true, score: securityScore(findings), findings },
    });
    expect(r.capped).toBe(true);
    expect(r.score).toBeLessThanOrEqual(49);
    expect(r.verdict).toBe("FAIL");
  });

  it("a clean run scores 100 and PASSes", () => {
    const r = assemble({
      functional: func({ ran: true, score: 100, passed: 3, total: 3 }),
      conformance: conf({ ran: true, score: 100 }),
      security: { ran: true, score: 100, findings: [] },
    });
    expect(r.score).toBe(100);
    expect(r.verdict).toBe("PASS");
  });

  it("a low-confidence medium finding does not cap", () => {
    const findings: Finding[] = [{ ruleId: "MCP07-auth", severity: "medium", confidence: "medium", message: "x" }];
    const r = assemble({
      functional: func({ ran: true, score: 100, passed: 1, total: 1 }),
      conformance: conf({ ran: true, score: 100 }),
      security: { ran: true, score: securityScore(findings), findings },
    });
    expect(r.capped).toBe(false);
    expect(r.verdict).toBe("PASS");
  });
});
