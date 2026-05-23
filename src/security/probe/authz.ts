// MCP07 — insufficient auth (HTTP only; N/A for stdio). MVP: if the server accepted
// our session with no token supplied, surface it as a medium-confidence finding (it
// may be intentionally public, so this never hard-FAILs on its own). Phase-5 will add
// the full RFC 9728 401 + WWW-Authenticate + /.well-known/oauth-protected-resource probe.
import { Finding } from "../../types.js";

export function probeAuth(transport: "stdio" | "http", url: string | undefined, unauthenticatedSucceeded: boolean): Finding[] {
  if (transport !== "http") return [];
  if (!unauthenticatedSucceeded) return [];
  return [
    {
      ruleId: "MCP07-auth",
      owasp: "MCP07:2025",
      severity: "medium",
      confidence: "medium",
      message: "Server accepted an unauthenticated MCP session (no token supplied). If this endpoint is not meant to be public, require OAuth per RFC 9728.",
      location: url ?? "(http endpoint)",
    },
  ];
}
