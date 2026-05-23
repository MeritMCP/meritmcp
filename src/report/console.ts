// Human-facing console verdict — the "green PASS / red FAIL" moment.
import { Report, Finding, Severity } from "../types.js";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

export function printReport(r: Report): void {
  const verdict = r.verdict === "PASS" ? `${GREEN}${BOLD}PASS${RESET}` : `${RED}${BOLD}FAIL${RESET}`;
  const capNote = r.capped ? `  ${RED}(capped — high-severity security finding)${RESET}` : "";
  console.log(`\nMerit — ${verdict} · Safety score ${scoreColor(r)}${r.score}/100${RESET}${capNote}\n`);

  if (r.functional.ran) {
    console.log(`Functional: ${r.functional.passed}/${r.functional.total} passed`);
    for (const t of r.functional.results) {
      const mark = t.passed ? `${GREEN}✔${RESET}` : `${RED}✖${RESET}`;
      console.log(`  ${mark} ${t.name}${t.passed ? "" : `\n      ${DIM}${t.detail}${RESET}`}`);
    }
  } else {
    console.log(`${DIM}Functional: skipped (no test file found)${RESET}`);
  }

  const d = r.functional.drift;
  if (d?.hasSnapshot) {
    if (!d.changed) {
      console.log(`${DIM}Schema: no drift${RESET}`);
    } else {
      const parts: string[] = [];
      if (d.removed.length) parts.push(`${RED}removed: ${d.removed.join(", ")}${RESET}`);
      if (d.schemaChanged.length) parts.push(`${RED}schema-changed: ${d.schemaChanged.join(", ")}${RESET}`);
      if (d.added.length) parts.push(`${GREEN}added: ${d.added.join(", ")}${RESET}`);
      if (d.descriptionOnly.length) parts.push(`${YELLOW}rug-pull: ${d.descriptionOnly.join(", ")}${RESET}`);
      console.log(`Schema drift — ${parts.join(" · ")}`);
    }
  } else {
    console.log(`${DIM}Schema: no snapshot yet (run \`merit snapshot\` to enable drift detection)${RESET}`);
  }

  const conf = r.conformance;
  if (conf.ran) {
    const skipped = conf.rawTotal - conf.total;
    console.log(
      `Conformance: ${conf.passed}/${conf.total} applicable scenarios passed (score ${conf.score}/100)` +
        `${skipped > 0 ? ` ${DIM}· ${skipped} N/A skipped${RESET}` : ""}`,
    );
    for (const s of conf.scenarios.filter((x) => x.applicable && !x.passed)) {
      console.log(`  ${RED}✖${RESET} ${s.scenario}${s.error ? `\n      ${DIM}${s.error}${RESET}` : ""}`);
    }
  } else {
    console.log(`${DIM}Conformance: skipped${conf.note ? ` (${conf.note})` : ""}${RESET}`);
  }

  if (r.security.ran) {
    const f = r.security.findings;
    const c = countBySeverity(f);
    const summary = f.length === 0 ? `${GREEN}no findings${RESET}` : severitySummary(c);
    console.log(`Security: ${summary} (score ${r.security.score}/100)`);
    for (const finding of sortBySeverity(f).slice(0, 8)) {
      console.log(
        `  ${sevMark(finding.severity)} [${finding.owasp ?? finding.ruleId}] ${finding.message}` +
          `${finding.location ? `\n      ${DIM}${finding.location}${RESET}` : ""}` +
          ` ${DIM}(${finding.confidence} confidence)${RESET}`,
      );
    }
  } else {
    console.log(`${DIM}Security: skipped${RESET}`);
  }
  console.log("");
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function severitySummary(c: Record<Severity, number>): string {
  const parts = SEV_ORDER.filter((s) => c[s] > 0).map((s) => `${c[s]} ${s}`);
  return `${RED}${parts.join(" · ")}${RESET}`;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
}

function sevMark(sev: Severity): string {
  if (sev === "critical" || sev === "high") return `${RED}✖${RESET}`;
  if (sev === "medium") return `${YELLOW}▲${RESET}`;
  return `${DIM}•${RESET}`;
}

function scoreColor(r: Report): string {
  if (r.verdict === "FAIL" || r.score < 30) return RED;
  if (r.score >= 85) return GREEN;
  if (r.score >= 50) return YELLOW;
  return RED;
}
