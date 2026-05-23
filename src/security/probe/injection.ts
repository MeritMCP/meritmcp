// MCP05 — command-injection probe. We only flag input reaching a real OS shell, proven
// two ways that a JS evaluator / input-reflector / error message physically cannot fake:
//   1. EXACT echo:  `echo <marker>` → output trims to EXACTLY <marker> (the shell ran echo
//      and returned only the marker). A tool that reflects input returns "echo <marker>";
//      a code evaluator throws an error that merely *contains* the marker — neither matches.
//   2. ARITHMETIC:  `…$((a*b))…` → output contains <marker><product>. Only a POSIX shell
//      expands `$((a*b))`; JS/cmd.exe/reflection keep the literal `$((a*b))`, so the
//      computed product never appears unless a shell actually evaluated it.
// This deliberately does NOT fire on tools that run code by design (e.g. browser_evaluate)
// — running JS in a sandbox is the feature, not OS command injection.
import { McpClient, ToolInfo } from "../../adapter/mcpClient.js";
import { Finding } from "../../types.js";

export async function probeInjection(client: McpClient, tools: ToolInfo[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const stringParams = stringPropsOf(tool.inputSchema);
    if (stringParams.length === 0) continue;

    let confirmed: { param: string; payload: string; how: string } | null = null;

    for (const param of stringParams) {
      const marker = `MCPV${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
      const a = 30 + Math.floor(Math.random() * 60);
      const b = 30 + Math.floor(Math.random() * 60);
      const product = a * b;
      const proof = `${marker}${product}`; // appears only if a shell echoed the marker AND expanded $((a*b))
      const arith = `$((${a}*${b}))`;
      const payloads = [
        `echo ${marker}`, // whole-input exec → exact-echo match (bash + cmd.exe)
        `${marker}${arith}`, // bash whole-input → "<marker><product>: not found"
        `; echo ${marker}${arith}`, // bash concatenation injection
        `& echo ${marker}${arith}`, // bash/cmd concatenation injection
        "`echo " + marker + arith + "`", // bash backtick injection
      ];

      for (const payload of payloads) {
        const args = baselineArgs(tool.inputSchema);
        args[param] = payload;
        let out = "";
        try {
          out = (await client.callTool(tool.name, args)).text;
        } catch {
          continue; // call rejected (e.g. validation) — not an injection signal
        }
        if (out.trim() === marker) {
          confirmed = { param, payload, how: "echo executed by a shell" };
          break;
        }
        if (out.includes(proof)) {
          confirmed = { param, payload, how: "shell arithmetic $((a*b)) expansion" };
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
        message: `Tool "${tool.name}" passed argument "${confirmed.param}" to an OS shell (confirmed via ${confirmed.how}; canary: ${confirmed.payload}).`,
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
