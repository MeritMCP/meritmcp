// MCP02 — privilege / scope creep. We flag only the HIGH-SIGNAL contradiction (to avoid
// noise): a tool annotated `readOnlyHint: true` whose name/description clearly implies a
// mutating or destructive action — a misleading "safe" label that can lull a client into
// auto-approving it. Heuristic → medium confidence (never hard-fails).
import { ToolInfo } from "../../adapter/mcpClient.js";
import { Finding } from "../../types.js";

const MUTATING =
  /\b(delete|drop|remove|destroy|truncate|wipe|erase|exec(?:ute)?|run[_-]?command|shell|write|overwrite|update|modify|insert|kill|terminate|revoke|grant|chmod|sudo|deploy|publish|transfer|withdraw)\b/i;

interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
}

export function scanPrivilege(tools: ToolInfo[]): Finding[] {
  const findings: Finding[] = [];
  for (const t of tools) {
    const ann = (t.annotations ?? {}) as ToolAnnotations;
    if (ann.readOnlyHint === true && MUTATING.test(`${t.name} ${t.description ?? ""}`)) {
      findings.push({
        ruleId: "MCP02-scope",
        owasp: "MCP02:2025",
        severity: "medium",
        confidence: "medium",
        message: `Tool "${t.name}" is annotated readOnlyHint:true but its name/description implies a mutating/destructive action — a misleading safety annotation.`,
        location: `mcp-server://tool/${t.name}`,
      });
    }
  }
  return findings;
}
