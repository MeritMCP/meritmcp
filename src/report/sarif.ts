// SARIF 2.1.0 output → GitHub code-scanning ("Security" tab). One run; security findings
// drive the security-severity ranking, and functional/drift/conformance failures show up
// as their own rules so the whole gate is visible in one place.
import { Report, Severity } from "../types.js";
import { RULES, securitySeverityNumber, sarifLevel } from "../security/owasp-map.js";
import { sha256 } from "../snapshot/canonicalize.js";

const INFO_URI = "https://github.com/meritmcp/meritmcp";

type Level = "error" | "warning" | "note";

interface Issue {
  ruleId: string;
  ruleName: string;
  shortDescription: string;
  level: Level;
  message: string;
  location: string;
  helpUri?: string;
  securitySeverity?: string;
  tags: string[];
}

export function toSarif(report: Report, version = "0.1.0"): object {
  const issues = collectIssues(report);
  const ruleMap = new Map<string, Issue>();
  for (const i of issues) if (!ruleMap.has(i.ruleId)) ruleMap.set(i.ruleId, i);

  const rules = [...ruleMap.values()].map((i) => ({
    id: i.ruleId,
    name: i.ruleName,
    shortDescription: { text: i.shortDescription },
    helpUri: i.helpUri ?? INFO_URI,
    defaultConfiguration: { level: i.level },
    properties: {
      ...(i.securitySeverity ? { "security-severity": i.securitySeverity } : {}),
      tags: i.tags,
    },
  }));

  const results = issues.map((i) => ({
    ruleId: i.ruleId,
    level: i.level,
    message: { text: i.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: i.location },
          region: { startLine: 1 },
        },
      },
    ],
    partialFingerprints: { merit: sha256(`${i.ruleId}|${i.location}|${i.message}`).slice(0, 20) },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Merit",
            informationUri: INFO_URI,
            version,
            rules,
          },
        },
        results,
      },
    ],
  };
}

function collectIssues(report: Report): Issue[] {
  const issues: Issue[] = [];

  // --- Security findings ---
  for (const f of report.security.findings) {
    const meta = RULES[f.ruleId];
    issues.push({
      ruleId: f.ruleId,
      ruleName: meta?.title ?? f.ruleId,
      shortDescription: meta?.title ?? f.ruleId,
      level: sarifLevel(f.severity),
      message: f.message,
      location: f.location ?? "mcp-server://",
      helpUri: meta?.helpUri,
      securitySeverity: securitySeverityNumber(f.severity),
      tags: ["security", "owasp-mcp", f.owasp ?? "", `confidence:${f.confidence}`].filter(Boolean),
    });
  }

  // --- Functional test failures ---
  for (const t of report.functional.results.filter((r) => !r.passed)) {
    issues.push({
      ruleId: "FUNCTIONAL-test-failed",
      ruleName: "Functional test failed",
      shortDescription: "A Merit functional test did not pass",
      level: "error",
      message: `${t.name}: ${t.detail}`,
      location: "mcp-server://functional",
      tags: ["functional"],
    });
  }

  // --- Schema drift ---
  const d = report.functional.drift;
  if (d?.hasSnapshot) {
    for (const n of d.removed) issues.push(driftIssue("DRIFT-tool-removed", "error", `Tool removed since snapshot: ${n}`, n, false));
    for (const n of d.schemaChanged) issues.push(driftIssue("DRIFT-schema-changed", "error", `Breaking schema change since snapshot: ${n}`, n, false));
    for (const n of d.descriptionOnly)
      issues.push(driftIssue("DRIFT-rug-pull", "warning", `Description-only change (possible tool-poisoning rug-pull): ${n}`, n, true));
  }

  // --- Conformance failures (applicable only) ---
  for (const s of report.conformance.scenarios.filter((x) => x.applicable && !x.passed)) {
    issues.push({
      ruleId: "CONFORMANCE-scenario-failed",
      ruleName: "Conformance scenario failed",
      shortDescription: "A scenario from the official MCP conformance suite failed",
      level: "warning",
      message: `${s.scenario}: ${s.error ?? "failed"}`,
      location: `mcp-server://conformance/${s.scenario}`,
      tags: ["conformance"],
    });
  }

  return issues;
}

function driftIssue(ruleId: string, level: Level, message: string, tool: string, security: boolean): Issue {
  return {
    ruleId,
    ruleName: ruleId,
    shortDescription: "Tool surface changed since the committed snapshot",
    level,
    message,
    location: `mcp-server://tool/${tool}`,
    securitySeverity: security ? securitySeverityNumber("medium" as Severity) : undefined,
    tags: security ? ["security", "schema-drift"] : ["schema-drift"],
  };
}
