// Scan ONE MCP server with Merit (static-only by default) and print a single JSON line.
// Run in isolation by expose.mjs so its entire process tree can be hard-killed afterward —
// this is what stops heavy/zombie server children from piling up and starving the runner.
import { run } from "../dist/src/orchestrator.js";

const command = process.argv[2];
const withConformance = process.argv.includes("--conformance");
if (!command) {
  console.error("usage: node scan-one.mjs <stdio-command> [--conformance]");
  process.exit(2);
}

try {
  const report = await run({
    connect: { transport: "stdio", command },
    testsPath: undefined,
    snapshotPath: undefined,
    security: true,
    probe: false, // never send live canary payloads to third-party servers
    conformance: withConformance,
  });
  const sev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of report.security.findings) sev[f.severity]++;
  process.stdout.write(
    JSON.stringify({
      ok: true,
      verdict: report.verdict,
      score: report.score,
      capped: report.capped,
      security: sev,
      findings: report.security.findings.map((f) => ({ rule: f.ruleId, owasp: f.owasp, sev: f.severity, conf: f.confidence, msg: f.message })),
      conformance: report.conformance.ran ? { passed: report.conformance.passed, total: report.conformance.total } : null,
    }),
  );
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e?.message ?? e) }));
}
process.exit(0);
