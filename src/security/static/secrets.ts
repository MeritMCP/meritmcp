// MCP01 — secret/token exposure. Doctrine: never regex-only. Known structured
// prefixes (AKIA…, ghp_…, sk-…) are inherently secrets → high confidence; generic
// high-entropy strings must ALSO clear an entropy bar AND sit near a secret keyword.
import { Finding } from "../../types.js";

interface SecretPattern {
  name: string;
  re: RegExp;
  structured: boolean; // structured prefix → high confidence on its own
}

const PATTERNS: SecretPattern[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g, structured: true },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, structured: true },
  { name: "OpenAI/Anthropic-style key", re: /\bsk-(?:live|test|proj|ant)?-?[A-Za-z0-9]{16,}\b/g, structured: true },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, structured: true },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, structured: true },
  { name: "Stripe secret key", re: /\bsk_live_[0-9A-Za-z]{16,}\b/g, structured: true },
  { name: "generic high-entropy secret", re: /\b[A-Za-z0-9+/_-]{24,}\b/g, structured: false },
];

const SECRET_KEYWORDS = /(secret|token|api[_-]?key|password|passwd|auth|credential|bearer|access[_-]?key)/i;

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
        const corroborated = p.structured || (shannonEntropy(secret) >= 3.2 && SECRET_KEYWORDS.test(window(inp.text, m.index)));
        if (!corroborated) continue;

        const dedupeKey = `${inp.location}:${secret.slice(0, 16)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        findings.push({
          ruleId: "MCP01-secret",
          owasp: "MCP01:2025",
          severity: "high",
          confidence: p.structured ? "high" : "medium",
          message: `Possible ${p.name} exposed in ${inp.label}: ${redact(secret)}`,
          location: inp.location,
        });
      }
    }
  }
  return findings;
}

function window(text: string, idx: number): string {
  return text.slice(Math.max(0, idx - 40), idx + 40);
}

function redact(s: string): string {
  return s.length <= 8 ? "****" : `${s.slice(0, 4)}…${s.slice(-2)}`;
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let e = 0;
  for (const k of Object.keys(freq)) {
    const pr = freq[k] / s.length;
    e -= pr * Math.log2(pr);
  }
  return e;
}
