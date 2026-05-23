// MCP09 — tool shadowing / impersonation. Two deterministic signals:
//  (a) DUPLICATE tool names — two tools claim the same name; one can shadow the other (high).
//  (b) NON-ASCII letters in a tool NAME — a homoglyph (e.g. a Cyrillic "е" in "rеad_file")
//      can impersonate a legitimate tool to a human or model. In a predominantly-ASCII tool
//      ecosystem, a non-ASCII character in a tool *name* is suspicious (medium).
import { ToolInfo } from "../../adapter/mcpClient.js";
import { Finding } from "../../types.js";

export function scanShadowing(tools: ToolInfo[]): Finding[] {
  const findings: Finding[] = [];

  const counts = new Map<string, number>();
  for (const t of tools) counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
  for (const [name, n] of counts) {
    if (n > 1) {
      findings.push({
        ruleId: "MCP09-shadow",
        owasp: "MCP09:2025",
        severity: "high",
        confidence: "high",
        message: `Duplicate tool name "${name}" declared ${n} times — one definition can shadow/impersonate the other.`,
        location: `mcp-server://tool/${name}`,
      });
    }
  }

  for (const t of tools) {
    const nonAscii = [...t.name].filter((ch) => (ch.codePointAt(0) ?? 0) > 0x7f);
    if (nonAscii.length > 0) {
      const cps = [...new Set(nonAscii)].map((c) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`);
      findings.push({
        ruleId: "MCP09-homoglyph",
        owasp: "MCP09:2025",
        severity: "high",
        confidence: "medium",
        message: `Tool name "${t.name}" contains non-ASCII character(s) (${cps.join(", ")}) — possible homoglyph impersonation of a legitimate tool.`,
        location: `mcp-server://tool/${t.name}`,
      });
    }
  }

  return findings;
}
