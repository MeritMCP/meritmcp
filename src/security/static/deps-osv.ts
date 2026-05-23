// MCP04 — supply-chain / dependency CVEs via OSV.dev (authoritative; we don't build
// a vuln DB). Needs --src pointing at the server's project. Prefers package-lock.json
// (resolved versions) over package.json. Network failure => skip (never crash the gate).
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Finding, Severity } from "../../types.js";

interface Dep {
  name: string;
  version: string;
}

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";
const DETAIL_LOOKUP_CAP = 40;

export async function scanDeps(srcDir: string): Promise<Finding[]> {
  const deps = collectNpmDeps(srcDir);
  if (deps.length === 0) return [];

  const queries = deps.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version }));

  let results: Array<{ vulns?: Array<{ id: string }> }>;
  try {
    const res = await fetch(OSV_BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) return [];
    results = ((await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> }).results ?? [];
  } catch {
    return []; // offline → skip
  }

  // Collect unique vuln ids, then enrich a bounded number with severity/summary.
  const hits: Array<{ dep: Dep; id: string }> = [];
  results.forEach((r, i) => {
    const dep = deps[i];
    for (const v of r.vulns ?? []) hits.push({ dep, id: v.id });
  });

  const details = await enrich(hits.slice(0, DETAIL_LOOKUP_CAP).map((h) => h.id));

  const findings: Finding[] = [];
  for (const h of hits) {
    const d = details.get(h.id);
    findings.push({
      ruleId: "MCP04-dep",
      owasp: "MCP04:2025",
      severity: d?.severity ?? "medium",
      confidence: "high",
      message: `${h.dep.name}@${h.dep.version}: ${h.id}${d?.summary ? ` — ${d.summary}` : ""}`,
      location: `package.json (${h.dep.name})`,
    });
  }
  return findings;
}

async function enrich(ids: string[]): Promise<Map<string, { severity: Severity; summary?: string }>> {
  const out = new Map<string, { severity: Severity; summary?: string }>();
  await Promise.all(
    ids.map(async (id) => {
      try {
        const res = await fetch(OSV_VULN + id);
        if (!res.ok) return;
        const v = (await res.json()) as { summary?: string; severity?: Array<{ score?: string }> };
        out.set(id, { severity: severityFromCvss(v.severity), summary: v.summary });
      } catch {
        /* ignore single-vuln lookup failures */
      }
    }),
  );
  return out;
}

function severityFromCvss(severity?: Array<{ score?: string }>): Severity {
  // OSV severity[].score is a CVSS vector string; pull the numeric base score if present.
  const vec = severity?.find((s) => s.score)?.score ?? "";
  const m = /\/?(?:CVSS:[\d.]+\/)?.*?(\d+(?:\.\d+)?)\b/.exec(vec);
  const n = m ? Number(m[1]) : NaN;
  if (Number.isNaN(n)) return "medium";
  if (n >= 9.0) return "critical";
  if (n >= 7.0) return "high";
  if (n >= 4.0) return "medium";
  return "low";
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
}

function collectNpmDeps(srcDir: string): Dep[] {
  const lock = join(srcDir, "package-lock.json");
  if (existsSync(lock)) {
    try {
      const j = readJson(lock) as { packages?: Record<string, { version?: string }> };
      const out: Dep[] = [];
      for (const [path, info] of Object.entries(j.packages ?? {})) {
        const marker = "node_modules/";
        const idx = path.lastIndexOf(marker);
        if (idx === -1 || !info.version) continue;
        out.push({ name: path.slice(idx + marker.length), version: info.version });
      }
      if (out.length) return dedupe(out);
    } catch {
      /* fall through to package.json */
    }
  }
  const pkgPath = join(srcDir, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const j = readJson(pkgPath) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const all = { ...j.dependencies, ...j.devDependencies };
      return Object.entries(all).map(([name, ver]) => ({ name, version: String(ver).replace(/^[\^~>=<\s]+/, "") }));
    } catch {
      return [];
    }
  }
  return [];
}

function dedupe(deps: Dep[]): Dep[] {
  const seen = new Set<string>();
  const out: Dep[] = [];
  for (const d of deps) {
    const k = `${d.name}@${d.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(d);
  }
  return out;
}
