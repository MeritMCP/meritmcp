// Markdown for the sticky PR comment (the Action posts it via actions/github-script).
// The HTML marker lets the Action find + update one comment instead of spamming.
import { Report, Finding, Severity } from "../types.js";

export const PR_COMMENT_MARKER = "<!-- merit-report -->";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function toMarkdown(report: Report): string {
  const verdict = report.verdict === "PASS" ? "✅ **PASS**" : "❌ **FAIL**";
  const cap = report.capped ? " _(capped — high-severity security finding)_" : "";

  const lines: string[] = [];
  lines.push(PR_COMMENT_MARKER);
  lines.push(`## Merit — ${verdict} · ${report.score}/100${cap}`);
  lines.push("");
  lines.push("| Check | Result | Weight |");
  lines.push("|---|---|---|");
  lines.push(`| Functional | ${cell(report.functional.ran, `${report.functional.passed}/${report.functional.total} passed`)} | 30% |`);
  lines.push(
    `| Conformance | ${cell(report.conformance.ran, `${report.conformance.passed}/${report.conformance.total} applicable passed`)} | 30% |`,
  );
  lines.push(`| Security | ${cell(report.security.ran, securityCell(report.security.findings))} | 40% |`);
  const d = report.functional.drift;
  lines.push(`| Schema | ${d?.hasSnapshot ? (d.changed ? "⚠️ drift detected" : "no drift") : "_no snapshot_"} | — |`);
  lines.push("");

  const findings = report.security.findings;
  if (findings.length) {
    lines.push("### Top security findings");
    for (const f of sortBySeverity(findings).slice(0, 8)) {
      lines.push(`- **${f.severity.toUpperCase()}** \`${f.owasp ?? f.ruleId}\` — ${f.message} _(${f.confidence} confidence)_`);
    }
    lines.push("");
  }

  const funcFails = report.functional.results.filter((r) => !r.passed);
  if (funcFails.length) {
    lines.push("### Failing functional tests");
    for (const t of funcFails.slice(0, 8)) lines.push(`- ❌ ${t.name} — ${t.detail}`);
    lines.push("");
  }

  lines.push("<sub>Full results in the **Security** tab (SARIF). Scoring is open + reproducible — see `merit.json`.</sub>");
  return lines.join("\n");
}

function cell(ran: boolean, text: string): string {
  return ran ? text : "_skipped_";
}

function securityCell(findings: Finding[]): string {
  if (findings.length === 0) return "✅ no findings";
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  return SEV_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(" · ");
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
}
