// Wraps the official MCP conformance suite, pinned to a known-good version. We never fork it
// — we shell out to it. To keep Merit's OWN dependency footprint tiny (the suite pulls in
// octokit + express), we do NOT bundle it: it's fetched on demand via npx, invoked through
// node's npx-cli (no shell; args passed as argv → injection-safe). If a user has installed
// @modelcontextprotocol/conformance locally, we use that copy instead (offline-friendly).
// Then we read the per-scenario checks.json files it writes to -o <dir>.
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
const CONFORMANCE_PKG = "@modelcontextprotocol/conformance";
const CONFORMANCE_VERSION = "0.1.16"; // pinned; isolated behind this wrapper (0.2.0 split incoming)

interface Launcher {
  cmd: string;
  prefix: string[];
  shell: boolean;
}

/** Prefer a locally-installed conformance (fast/offline); else fetch on demand via npx. */
function conformanceLauncher(): Launcher | null {
  try {
    const bin = join(dirname(require.resolve(`${CONFORMANCE_PKG}/package.json`)), "dist", "index.js");
    return { cmd: process.execPath, prefix: [bin], shell: false };
  } catch {
    /* not installed — fetch on demand below */
  }
  const npxCli = findNpxCli();
  if (npxCli) return { cmd: process.execPath, prefix: [npxCli, "-y", `${CONFORMANCE_PKG}@${CONFORMANCE_VERSION}`], shell: false };
  // Last resort: npx through a shell (the only path that needs a shell, for npx.cmd on Windows).
  return { cmd: process.platform === "win32" ? "npx.cmd" : "npx", prefix: ["-y", `${CONFORMANCE_PKG}@${CONFORMANCE_VERSION}`], shell: true };
}

function findNpxCli(): string | null {
  const dir = dirname(process.execPath);
  for (const c of [join(dir, "node_modules", "npm", "bin", "npx-cli.js"), join(dir, "..", "lib", "node_modules", "npm", "bin", "npx-cli.js")]) {
    if (existsSync(c)) return c;
  }
  return null;
}

export interface ConformanceOptions {
  transport: "stdio" | "http";
  capabilities?: Record<string, unknown>;
  suite?: string; // active | all | pending
  baseline?: string; // path to an --expected-failures YAML
  timeoutMs?: number;
}

export async function runConformance(url: string, opts: ConformanceOptions): Promise<ConformanceOutcome> {
  const launcher = conformanceLauncher();
  if (!launcher) return notRun("could not locate node/npx to run the conformance suite");

  const outDir = mkdtempSync(join(tmpdir(), "merit-conf-"));
  const suiteArgs = ["server", "--url", url, "--suite", opts.suite ?? "active", "-o", outDir, "--verbose"];
  if (opts.baseline && existsSync(opts.baseline)) suiteArgs.push("--expected-failures", opts.baseline);

  try {
    // First on-demand run may download the suite via npx → allow generous time.
    await exec(launcher.cmd, [...launcher.prefix, ...suiteArgs], opts.timeoutMs ?? 300000, launcher.shell);
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

function exec(cmd: string, args: string[], timeoutMs: number, shell = false): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { shell });
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
