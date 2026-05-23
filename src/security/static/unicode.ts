// MCP03a — invisible/abusable Unicode in tool metadata. Deterministic (~0 FP):
// these characters are hidden from a human reading the description but the model
// still ingests them — the classic "tool poisoning" vector.
import { Finding } from "../../types.js";

const CATEGORIES: Array<{ name: string; match: (cp: number) => boolean }> = [
  { name: "zero-width character", match: (cp) => [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff].includes(cp) },
  { name: "bidirectional override", match: (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) },
  { name: "Unicode tag character", match: (cp) => cp >= 0xe0000 && cp <= 0xe007f },
  { name: "soft hyphen / format control", match: (cp) => cp === 0x00ad },
];

export interface UnicodeInput {
  label: string;
  text: string;
  location: string;
}

export function scanUnicode(inputs: UnicodeInput[]): Finding[] {
  const findings: Finding[] = [];

  for (const inp of inputs) {
    const hits = new Map<string, Set<number>>();
    for (const ch of inp.text) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;
      for (const cat of CATEGORIES) {
        if (cat.match(cp)) {
          const set = hits.get(cat.name) ?? new Set<number>();
          set.add(cp);
          hits.set(cat.name, set);
        }
      }
    }
    for (const [cat, cps] of hits) {
      const labels = [...cps].map((c) => `U+${c.toString(16).toUpperCase().padStart(4, "0")}`);
      findings.push({
        ruleId: "MCP03a-unicode",
        owasp: "MCP03:2025",
        severity: "high",
        confidence: "high",
        message: `Hidden ${cat} (${labels.join(", ")}) in ${inp.label} — classic tool-poisoning vector.`,
        location: inp.location,
      });
    }
  }
  return findings;
}
