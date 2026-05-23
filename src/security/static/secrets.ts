// MCP01 — secret/token exposure. HIGH-PRECISION by design: we only flag well-known
// STRUCTURED credential formats, which are unmistakable. We deliberately do NOT flag
// "generic high-entropy strings" — in tool metadata those are almost always identifiers /
// IDs / hashes (e.g. a tool named `monarch_login_with_token`), and a security scanner that
// cries wolf gets dunked. Each pattern carries its own severity + confidence; only the few
// that can be an innocent doc example (JWT, GCP marker) are medium-confidence.
import { Finding, Severity, Confidence } from "../../types.js";

interface SecretPattern {
  name: string;
  re: RegExp;
  severity?: Severity; // default "high"
  confidence?: Confidence; // default "high"
}

const PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "GitHub fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g },
  { name: "OpenAI/Anthropic-style key", re: /\bsk-(?:live|test|proj|ant)?-?[A-Za-z0-9]{20,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "Slack webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{40,}/g },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g },
  { name: "npm access token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "Azure storage AccountKey", re: /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/g },
  { name: "private key (PEM block)", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: "critical" },
  { name: "GCP service-account key", re: /"type"\s*:\s*"service_account"/g, severity: "critical", confidence: "medium" },
  { name: "JSON Web Token (JWT)", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, confidence: "medium" },
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
        const dedupeKey = `${inp.location}:${p.name}:${secret.slice(0, 16)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        findings.push({
          ruleId: "MCP01-secret",
          owasp: "MCP01:2025",
          severity: p.severity ?? "high",
          confidence: p.confidence ?? "high",
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
