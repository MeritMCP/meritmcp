// MCP05 — command-injection probe. For each string argument we send a benign canary
// (`echo MCPV_<rand>` plus shell-metachar variants). If the marker comes back but the
// literal payload does NOT (i.e., the wrapper was evaluated, not echoed verbatim), the
// input reached a shell → confirmed injection (high confidence). A tool that merely
// echoes input returns the payload verbatim → PASS. Portable across bash and cmd.exe.
import { McpClient, ToolInfo } from "../../adapter/mcpClient.js";
import { Finding } from "../../types.js";

export async function probeInjection(client: McpClient, tools: ToolInfo[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const stringParams = stringPropsOf(tool.inputSchema);
    if (stringParams.length === 0) continue;

    let confirmed: { param: string; payload: string } | null = null;

    for (const param of stringParams) {
      const marker = `MCPV_${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
      const payloads = [`echo ${marker}`, `; echo ${marker}`, `& echo ${marker}`, `$(echo ${marker})`, "`echo " + marker + "`"];

      for (const payload of payloads) {
        const args = baselineArgs(tool.inputSchema);
        args[param] = payload;
        let out = "";
        try {
          out = (await client.callTool(tool.name, args)).text;
        } catch {
          continue; // call rejected (e.g. validation) — not an injection signal
        }
        if (out.includes(marker) && !out.includes(payload)) {
          confirmed = { param, payload };
          break;
        }
      }
      if (confirmed) break;
    }

    if (confirmed) {
      findings.push({
        ruleId: "MCP05-cmd-injection",
        owasp: "MCP05:2025",
        severity: "critical",
        confidence: "high",
        message: `Tool "${tool.name}" evaluated a shell payload in argument "${confirmed.param}" (canary executed: ${confirmed.payload}).`,
        location: `mcp-server://tool/${tool.name}`,
      });
    }
  }
  return findings;
}

interface JsonSchema {
  type?: string;
  properties?: Record<string, { type?: string }>;
  required?: string[];
}

function stringPropsOf(schema: unknown): string[] {
  const s = schema as JsonSchema | undefined;
  if (!s?.properties) return [];
  return Object.entries(s.properties)
    .filter(([, def]) => def.type === "string")
    .map(([name]) => name);
}

/** Fill required params with benign placeholders so unrelated validation doesn't reject the probe. */
function baselineArgs(schema: unknown): Record<string, unknown> {
  const s = schema as JsonSchema | undefined;
  const out: Record<string, unknown> = {};
  if (!s?.properties) return out;
  for (const name of s.required ?? []) {
    const def = s.properties[name];
    if (!def) continue;
    out[name] = def.type === "number" || def.type === "integer" ? 1 : def.type === "boolean" ? true : "test";
  }
  return out;
}
