// MCP01 — secret/token exposure. HIGH-PRECISION by design: we only flag well-known
// STRUCTURED credential formats (AWS / GitHub / OpenAI-style / Google / Slack / Stripe),
// which are unmistakable. We deliberately do NOT flag "generic high-entropy strings": in
// tool metadata those are almost always identifiers / IDs / hashes (e.g. a tool literally
// named `monarch_login_with_token`), and a security scanner that cries wolf gets dunked.
import { Finding } from "../../types.js";

interface SecretPattern {
  name: string;
  re: RegExp;
}

const PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "OpenAI/Anthropic-style key", re: /\bsk-(?:live|test|proj|ant)?-?[A-Za-z0-9]{20,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "Stripe secret key", re: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
];

export interface ScanInput {
  label: string;
  text: string;
  location: string;
}

export function scanSecrets(inputs: ScanInput[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const inp of inputs) {
    for (const p of PATTERNS) {
      p.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = p.re.exec(inp.text)) !== null) {
        const secret = m[0];
        const dedupeKey = `${inp.location}:${secret.slice(0, 16)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        findings.push({
          ruleId: "MCP01-secret",
          owasp: "MCP01:2025",
          severity: "high",
          confidence: "high", // only unmistakable structured formats reach here
          message: `Possible ${p.name} exposed in ${inp.label}: ${redact(secret)}`,
          location: inp.location,
        });
      }
    }
  }
  return findings;
}

function redact(s: string): string {
  return s.length <= 8 ? "****" : `${s.slice(0, 4)}…${s.slice(-2)}`;
}
