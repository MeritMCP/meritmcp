// Security engine: runs the 5 high-confidence MVP checks (static + probe) and returns
// the findings + a 0–100 security sub-score. Static = tool-metadata + deps; probe = live.
import { McpClient, ToolInfo } from "../adapter/mcpClient.js";
import { Finding } from "../types.js";
import { scanSecrets } from "./static/secrets.js";
import { scanUnicode } from "./static/unicode.js";
import { scanDeps } from "./static/deps-osv.js";
import { probeInjection } from "./probe/injection.js";
import { probeAuth } from "./probe/authz.js";
import { securityScore } from "../report/score.js";

export interface SecurityInput {
  client: McpClient;
  tools: ToolInfo[];
  transport: "stdio" | "http";
  url?: string;
  srcDir?: string;
  probe: boolean; // live probes can be disabled with --no-probe
}

export interface SecurityResult {
  findings: Finding[];
  score: number;
}

export async function runSecurity(input: SecurityInput): Promise<SecurityResult> {
  const findings: Finding[] = [];

  // --- STATIC: tool metadata (names + descriptions) ---
  const metaInputs = input.tools.map((t) => ({
    label: `tool "${t.name}" metadata`,
    text: `${t.name}\n${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`,
    location: `mcp-server://tool/${t.name}`,
  }));
  findings.push(...scanSecrets(metaInputs));
  findings.push(...scanUnicode(metaInputs));

  // --- STATIC: dependencies (requires --src) ---
  if (input.srcDir) findings.push(...(await scanDeps(input.srcDir)));

  // --- PROBE: command injection ---
  if (input.probe) findings.push(...(await probeInjection(input.client, input.tools)));

  // --- PROBE: auth (HTTP only) ---
  findings.push(...probeAuth(input.transport, input.url, input.transport === "http"));

  return { findings, score: securityScore(findings) };
}
