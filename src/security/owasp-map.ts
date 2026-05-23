// Stable rule IDs ↔ OWASP MCP Top 10 (Beta v0.1). Every finding carries BOTH our
// rule id and the OWASP id, so OWASP re-ordering never breaks consumers (04-SECURITY-OWASP.md).
import { Severity } from "../types.js";

export const OWASP_HELP = "https://owasp.org/www-project-mcp-top-10/";

export interface RuleMeta {
  ruleId: string;
  owasp: string;
  title: string;
  defaultSeverity: Severity;
  remediation: string;
  helpUri: string;
}

export const RULES: Record<string, RuleMeta> = {
  "MCP02-scope": {
    ruleId: "MCP02-scope",
    owasp: "MCP02:2025",
    title: "Misleading tool annotation (privilege/scope)",
    defaultSeverity: "medium",
    remediation: "A tool that mutates state must not be annotated readOnlyHint:true. Mark mutating tools with destructiveHint and accurate hints so clients can warn the user.",
    helpUri: OWASP_HELP,
  },
  "MCP09-shadow": {
    ruleId: "MCP09-shadow",
    owasp: "MCP09:2025",
    title: "Duplicate tool name (shadowing)",
    defaultSeverity: "high",
    remediation: "Ensure every tool name is unique; a duplicate definition can shadow or impersonate another tool.",
    helpUri: OWASP_HELP,
  },
  "MCP09-homoglyph": {
    ruleId: "MCP09-homoglyph",
    owasp: "MCP09:2025",
    title: "Non-ASCII / homoglyph tool name (impersonation)",
    defaultSeverity: "high",
    remediation: "Use ASCII tool names; non-ASCII look-alike characters can impersonate a legitimate tool to humans and models.",
    helpUri: OWASP_HELP,
  },
  "MCP01-secret": {
    ruleId: "MCP01-secret",
    owasp: "MCP01:2025",
    title: "Exposed secret or token",
    defaultSeverity: "high",
    remediation: "Remove the credential from tool metadata/output; load it from an environment variable or secret store at runtime and rotate the leaked value.",
    helpUri: OWASP_HELP,
  },
  "MCP03a-unicode": {
    ruleId: "MCP03a-unicode",
    owasp: "MCP03:2025",
    title: "Invisible/abusable Unicode in tool metadata (tool poisoning)",
    defaultSeverity: "high",
    remediation: "Strip zero-width, bidirectional-override and tag characters from tool names/descriptions/schemas; they hide instructions from humans while the model still reads them.",
    helpUri: OWASP_HELP,
  },
  "MCP04-dep": {
    ruleId: "MCP04-dep",
    owasp: "MCP04:2025",
    title: "Vulnerable dependency",
    defaultSeverity: "medium",
    remediation: "Upgrade the dependency to a fixed version (see the linked OSV/GHSA advisory).",
    helpUri: OWASP_HELP,
  },
  "MCP05-cmd-injection": {
    ruleId: "MCP05-cmd-injection",
    owasp: "MCP05:2025",
    title: "Command injection",
    defaultSeverity: "critical",
    remediation: "Never pass tool input to a shell. Use argument arrays (execFile/spawn without a shell), strict allow-lists, and input validation.",
    helpUri: OWASP_HELP,
  },
  "MCP07-auth": {
    ruleId: "MCP07-auth",
    owasp: "MCP07:2025",
    title: "Insufficient authentication / authorization",
    defaultSeverity: "high",
    remediation: "Require auth on the MCP endpoint; return 401 with an RFC 9728 WWW-Authenticate header and publish /.well-known/oauth-protected-resource.",
    helpUri: OWASP_HELP,
  },
};

/** SARIF security-severity is a 0.1–10.0 string (drives GitHub code-scanning ranking). */
export function securitySeverityNumber(sev: Severity): string {
  return { critical: "9.5", high: "8.0", medium: "5.0", low: "3.0" }[sev];
}

/** SARIF level for defaultConfiguration. */
export function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}
