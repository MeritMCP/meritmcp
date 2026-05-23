// Wraps the official MCP conformance suite (@modelcontextprotocol/conformance@0.1.16).
// We never fork it — we spawn it (via `node <bin>`, no shell, so args are safe) against an
// HTTP URL, then read the per-scenario checks.json files it writes to -o <dir>.
//
// Scoring is capability- and transport-aware: a tools-only server shouldn't be punished for
// not implementing resources/prompts/logging, and HTTP-transport scenarios (dns-rebinding,
// sse) reflect our stdio→HTTP proxy, not a stdio target — both are excluded from the score.
import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";
import { ConformanceOutcome, ConformanceScenario } from "../types.js";

const require = createRequire(import.meta.url);

export interface ConformanceOptions {
  transport: "stdio" | "http";
  capabilities?: Record<string, unknown>;
  suite?: string; // active | all | pending
  baseline?: string; // path to an --expected-failures YAML
  timeoutMs?: number;
}

export async function runConformance(url: string, opts: ConformanceOptions): Promise<ConformanceOutcome> {
  let binJs: string;
  try {
    binJs = join(dirname(require.resolve("@modelcontextprotocol/conformance/package.json")), "dist", "index.js");
  } catch {
    return notRun("conformance package not installed");
  }

  const outDir = mkdtempSync(join(tmpdir(), "merit-conf-"));
  const args = [binJs, "server", "--url", url, "--suite", opts.suite ?? "active", "-o", outDir, "--verbose"];
  if (opts.baseline && existsSync(opts.baseline)) args.push("--expected-failures", opts.baseline);

  try {
    await exec(process.execPath, args, opts.timeoutMs ?? 180000);
  } catch (e) {
    cleanup(outDir);
    return notRun(`could not run conformance: ${(e as Error).message}`);
  }

  const scenarios = parseScenarios(outDir, opts);
  cleanup(outDir);

  if (scenarios.length === 0) return notRun("conformance produced no results (is the server reachable?)");

  const applicable = scenarios.filter((s) => s.applicable);
  const passed = applicable.filter((s) => s.passed).length;
  const total = applicable.length;
  return {
    ran: true,
    score: total === 0 ? 100 : Math.round((100 * passed) / total),
    passed,
    total,
    rawPassed: scenarios.filter((s) => s.passed).length,
    rawTotal: scenarios.length,
    scenarios,
  };
}

function parseScenarios(outDir: string, opts: ConformanceOptions): ConformanceScenario[] {
  const out: ConformanceScenario[] = [];
  for (const entry of readdirSync(outDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const scenario = entry.name.replace(/^server-/, "").replace(/-\d{4}-\d{2}-\d{2}T.*Z$/, "");
    const checksPath = join(outDir, entry.name, "checks.json");
    if (!existsSync(checksPath)) continue;
    let checks: Array<{ status?: string; errorMessage?: string }>;
    try {
      checks = JSON.parse(readFileSync(checksPath, "utf8"));
    } catch {
      continue;
    }
    const passed = checks.length > 0 && checks.every((c) => c.status === "SUCCESS");
    const error = checks.find((c) => c.status !== "SUCCESS")?.errorMessage;
    out.push({ scenario, passed, error, applicable: isApplicable(scenario, opts) });
  }
  return out.sort((a, b) => a.scenario.localeCompare(b.scenario));
}

// Allowlist of conformance scenarios that are *universally* checkable against an arbitrary
// server for a declared capability — pinned to conformance 0.1.16. We deliberately EXCLUDE:
//   • named-fixture scenarios (prompts-get-*, resources-read-*, completion-complete) — these
//     dereference items only the SDK's internal reference server defines (test://static-text,
//     test_simple_prompt…), so every real server "fails" them for the wrong reason;
//   • content/feature-specific tool scenarios (image/audio/progress/sampling/elicitation);
//   • HTTP-transport scenarios (dns-rebinding, sse) when proxying a stdio target — they test
//     our proxy, not the server.
// What remains is the honest core: "does your server correctly implement the protocol surface
// it declares?" (initialize, ping, the *-list scenarios, a basic tool call + error, log level).
function isApplicable(scenario: string, opts: ConformanceOptions): boolean {
  const caps = opts.capabilities ?? {};
  const has = (k: string) => caps[k] !== undefined && caps[k] !== null;

  switch (scenario) {
    case "server-initialize":
    case "ping":
      return true;
    case "tools-list":
    case "tools-call-simple-text":
    case "tools-call-error":
      return has("tools");
    case "resources-list":
      return has("resources");
    case "prompts-list":
      return has("prompts");
    case "logging-set-level":
      return has("logging");
    case "dns-rebinding-protection":
      return opts.transport === "http";
    default:
      if (scenario.startsWith("server-sse")) return opts.transport === "http";
      return false;
  }
}

function exec(cmd: string, args: string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { shell: false });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("conformance timed out"));
    }, timeoutMs);
    // Drain pipes so the child never blocks on a full buffer.
    child.stdout?.on("data", () => {});
    child.stderr?.on("data", () => {});
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    // Conformance exits non-zero when scenarios fail — that's expected, not an error.
    child.on("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function cleanup(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

function notRun(note: string): ConformanceOutcome {
  return { ran: false, score: null, passed: 0, total: 0, rawPassed: 0, rawTotal: 0, scenarios: [], note };
}
