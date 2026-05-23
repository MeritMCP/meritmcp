// The exposé scanner: run Merit across a list of real MCP servers (scripts/servers.json,
// produced by fetch-registry.mjs) and emit a ranked leaderboard + headline stats.
//
// SAFETY: this installs + launches third-party servers, so run it ONLY in a disposable
// sandbox (the GitHub Actions `expose` workflow). It is static-only by default — it NEVER
// sends live probe payloads, and conformance (which calls one tool per server) is opt-in.
// Not part of the npm package (scripts/ is never published). Usage:
//   node scripts/fetch-registry.mjs --limit=100 && node scripts/expose.mjs [--conformance]
import { readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const SCAN_ONE = fileURLToPath(new URL("./scan-one.mjs", import.meta.url));
const servers = JSON.parse(readFileSync(new URL("./servers.json", import.meta.url), "utf8"));
// Opt-in: conformance CALLS tools (tools-call-simple-text), which can have real side
// effects on powerful third-party servers (browser nav, command exec). Off by default.
const withConformance = process.argv.includes("--conformance");
const PER_SERVER_TIMEOUT = withConformance ? 300000 : 60000; // static = fast; conformance needs room

// Scan one server in an ISOLATED subprocess (scan-one.mjs), then hard-kill its entire
// process group. Untrusted servers spawn heavy/zombie children (browsers, native builds)
// that don't die on disconnect; without this they pile up and starve the CI runner
// ("the hosted runner lost communication"). One group per server, reaped every time.
function scanOne(command, timeoutMs) {
  return new Promise((resolve) => {
    const args = [SCAN_ONE, command];
    if (withConformance) args.push("--conformance");
    const child = spawn(process.execPath, args, {
      detached: process.platform !== "win32", // own process group on POSIX → killable as a group
      stdio: ["ignore", "pipe", "ignore"], // ignore the server's noisy stderr
    });
    let out = "";
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        if (process.platform === "win32") spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
        else process.kill(-child.pid, "SIGKILL"); // kill the whole group (server + its children)
      } catch {
        /* already gone */
      }
      resolve(result);
    };
    const timer = setTimeout(() => finish({ ok: false, error: `timed out after ${Math.round(timeoutMs / 1000)}s` }), timeoutMs);
    child.stdout.on("data", (d) => (out += d));
    child.on("error", (e) => finish({ ok: false, error: String(e.message) }));
    child.on("close", () => {
      try {
        finish(JSON.parse(out.trim()));
      } catch {
        finish({ ok: false, error: "no result from scan subprocess (crashed?)" });
      }
    });
  });
}

const results = [];
let i = 0;
for (const s of servers) {
  process.stderr.write(`▶ [${++i}/${servers.length}] ${s.name} …\n`);
  const t0 = Date.now();
  const res = await scanOne(s.command, PER_SERVER_TIMEOUT);
  res.name = s.name;
  res.ms = Date.now() - t0;
  results.push(res);
  process.stderr.write(`  ${res.ok ? `${res.verdict} · ${res.score}/100` : `✖ ${res.error}`}\n`);
}

const scanned = results.filter((r) => r.ok);
const errored = results.filter((r) => !r.ok);
const failed = scanned.filter((r) => r.verdict === "FAIL");
const withAnyFinding = scanned.filter((r) => r.findings.length > 0);
const withHighSev = scanned.filter((r) => r.security.critical + r.security.high > 0);
const withHighConf = scanned.filter((r) => r.findings.some((f) => f.conf === "high" && (f.sev === "critical" || f.sev === "high")));
const avg = scanned.length ? Math.round(scanned.reduce((a, r) => a + r.score, 0) / scanned.length) : 0;
const pct = (n, d) => (d ? `${Math.round((100 * n) / d)}%` : "0%");

writeFileSync("expose-results.json", JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2));

let md = `# The MCP Server Trust Report\n\n`;
md += `_Scanned ${scanned.length} of ${results.length} attempted MCP servers with [Merit](https://github.com/MeritMCP/meritmcp) on ${new Date().toISOString().slice(0, 10)} (${errored.length} couldn't run unconfigured)._\n\n`;
md += `## Headline\n`;
md += `- **${pct(failed.length, scanned.length)}** of scanned servers **FAIL** the gate.\n`;
md += `- **${pct(withAnyFinding.length, scanned.length)}** have ≥1 security finding; **${pct(withHighSev.length, scanned.length)}** a Critical/High-severity one; **${pct(withHighConf.length, scanned.length)}** a *high-confidence* Critical/High (the kind that hard-fails).\n`;
md += `- **${pct(errored.length, results.length)}** of registry servers wouldn't even start without config/keys.\n`;
md += `- Average safety score (of those scanned): **${avg}/100**.\n\n`;
md += `## Leaderboard (worst first)\n\n`;
md += `| Server | Verdict | Score | Crit | High | Med | Conformance |\n|---|---|---|---|---|---|---|\n`;
for (const r of [...scanned].sort((a, b) => a.score - b.score)) {
  const c = r.conformance ? `${r.conformance.passed}/${r.conformance.total}` : "—";
  md += `| \`${r.name}\` | ${r.verdict === "PASS" ? "✅ PASS" : "❌ FAIL"} | ${r.score} | ${r.security.critical} | ${r.security.high} | ${r.security.medium} | ${c} |\n`;
}
const flagged = scanned.filter((r) => r.findings.length > 0);
if (flagged.length) {
  md += `\n## Findings — VERIFY each before citing publicly\n\n`;
  md += `_(medium/low-confidence findings are heuristics, not confirmed; e.g. "generic high-entropy secret" can be an example ID or hash, not a real credential.)_\n\n`;
  for (const r of flagged) {
    md += `**\`${r.name}\`** — score ${r.score}\n`;
    for (const f of r.findings) md += `- **${f.sev}** / ${f.conf}-confidence · \`${f.owasp ?? f.rule}\` — ${f.msg}\n`;
    md += `\n`;
  }
}
if (errored.length) {
  md += `\n## Could not scan (need config/keys, timed out, or crashed on launch)\n`;
  for (const r of errored) md += `- \`${r.name}\` — ${r.error}\n`;
}
md += `\n<sub>Generated by Merit — the CI quality gate for MCP servers. https://github.com/MeritMCP/meritmcp</sub>\n`;
writeFileSync("LEADERBOARD.md", md);
console.log("\n" + md);

// Some scanned servers spawn child processes / leave pipes open that don't die when their
// connection closes, which keeps Node's event loop alive forever (the "stuck after the
// report" hang). The report + JSON are already written, so force a clean exit.
process.exit(0);
