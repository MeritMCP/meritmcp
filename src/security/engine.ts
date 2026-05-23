// Security engine: runs the OWASP-MCP-Top-10 checks (static + opt-in probe) and returns
// the findings + a 0–100 security sub-score. Static = tool-metadata + deps; probe = live.
import { McpClient, ToolInfo } from "../adapter/mcpClient.js";
import { Finding } from "../types.js";
import { scanSecrets } from "./static/secrets.js";
import { scanUnicode } from "./static/unicode.js";
import { scanDeps } from "./static/deps-osv.js";
import { scanShadowing } from "./static/shadowing.js";
import { scanPrivilege } from "./static/privilege.js";
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
  findings.push(...scanSecrets(metaInputs)); // MCP01
  findings.push(...scanUnicode(metaInputs)); // MCP03a
  findings.push(...scanShadowing(input.tools)); // MCP09 (duplicate / homoglyph tool names)
  findings.push(...scanPrivilege(input.tools)); // MCP02 (misleading readOnlyHint)

  // --- STATIC: dependencies (requires --src) ---
  if (input.srcDir) findings.push(...(await scanDeps(input.srcDir))); // MCP04

  // --- PROBE: command injection ---
  if (input.probe) findings.push(...(await probeInjection(input.client, input.tools)));

  // --- PROBE: auth (HTTP only) ---
  findings.push(...probeAuth(input.transport, input.url, input.transport === "http"));

  return { findings, score: securityScore(findings) };
}
