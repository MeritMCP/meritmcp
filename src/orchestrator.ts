// Wires the engines together into one Report. MVP runs functional + schema-drift;
// conformance + security are declared "not run" and the scorer redistributes weight.
import { existsSync, readFileSync } from "node:fs";
import { McpClient, ConnectOptions } from "./adapter/mcpClient.js";
import { runFunctional } from "./functional/runner.js";
import { capture, Snapshot } from "./snapshot/capture.js";
import { diff } from "./snapshot/diff.js";
import { assemble, DEFAULT_SCORING } from "./report/score.js";
import { runSecurity } from "./security/engine.js";
import { runConformance } from "./conformance/wrapper.js";
import { startStdioHttpProxy } from "./conformance/stdio-proxy.js";
import { Report, FunctionalOutcome, DriftSummary, TestResult, SecurityOutcome, ConformanceOutcome } from "./types.js";

export interface RunConfig {
  connect: ConnectOptions;
  testsPath?: string;
  snapshotPath?: string;
  srcDir?: string;
  security?: boolean; // default true
  probe?: boolean; // default true
  conformance?: boolean; // default true
  conformanceBaseline?: string;
}

const NOT_RUN_CONFORMANCE: ConformanceOutcome = {
  ran: false,
  score: null,
  passed: 0,
  total: 0,
  rawPassed: 0,
  rawTotal: 0,
  scenarios: [],
};

export async function run(cfg: RunConfig): Promise<Report> {
  const client = new McpClient();
  await client.connect(cfg.connect);
  try {
    const tools = await client.listTools();

    // --- Functional engine ---
    let results: TestResult[] = [];
    let functionalRan = false;
    if (cfg.testsPath && existsSync(cfg.testsPath)) {
      results = await runFunctional(client, cfg.testsPath);
      functionalRan = true;
    }

    // --- Schema-drift (part of the functional engine) ---
    let drift: DriftSummary;
    if (cfg.snapshotPath && existsSync(cfg.snapshotPath)) {
      const prev = JSON.parse(readFileSync(cfg.snapshotPath, "utf8")) as Snapshot;
      drift = diff(prev, capture(tools));
    } else {
      drift = { hasSnapshot: false, changed: false, added: [], removed: [], schemaChanged: [], descriptionOnly: [] };
    }

    const passed = results.filter((r) => r.passed).length;
    const total = results.length;
    const functional: FunctionalOutcome = {
      ran: functionalRan,
      score: functionalRan ? (total === 0 ? 100 : Math.round((100 * passed) / total)) : null,
      passed,
      total,
      results,
      drift,
    };

    // --- Security engine (OWASP-MCP-Top-10, 5 high-confidence MVP checks) ---
    let security: SecurityOutcome = { ran: false, score: null, findings: [] };
    if (cfg.security ?? true) {
      const sec = await runSecurity({
        client,
        tools,
        transport: cfg.connect.transport,
        url: cfg.connect.url,
        srcDir: cfg.srcDir,
        probe: cfg.probe ?? true,
      });
      security = { ran: true, score: sec.score, findings: sec.findings };
    }

    // --- Conformance (wrap the official suite; proxy stdio→HTTP since it's HTTP-only) ---
    const capabilities = client.serverCapabilities();
    let conformance: ConformanceOutcome = NOT_RUN_CONFORMANCE;
    if (cfg.conformance ?? true) {
      if (cfg.connect.transport === "http") {
        conformance = await runConformance(cfg.connect.url!, {
          transport: "http",
          capabilities,
          baseline: cfg.conformanceBaseline,
        });
      } else if (cfg.connect.command) {
        const proxy = await startStdioHttpProxy(cfg.connect.command);
        try {
          conformance = await runConformance(proxy.url, {
            transport: "stdio",
            capabilities,
            baseline: cfg.conformanceBaseline,
          });
        } finally {
          await proxy.close();
        }
      }
    }

    return assemble({ functional, conformance, security }, DEFAULT_SCORING);
  } finally {
    await client.close();
  }
}
