// The open, reproducible scoring model (01-DESIGN.md). Weights for engines that did
// not run are redistributed across the engines that did, so a functional-only run in
// the MVP still produces an honest number. The security cap is the integrity rule:
// any high-confidence Critical/High caps the total at 49 and forces FAIL.
import { Report, FunctionalOutcome, ConformanceOutcome, SecurityOutcome, Finding } from "../types.js";

export interface ScoringConfig {
  weights: { functional: number; conformance: number; security: number };
  securityPenalties: { critical: number; high: number; medium: number; low: number };
  confidenceMultiplier: { high: number; medium: number; low: number };
  rugPullPenalty: number;
  capScore: number;
  bands: { brightgreen: number; green: number; yellow: number; red: number };
}

export const DEFAULT_SCORING: ScoringConfig = {
  weights: { functional: 0.3, conformance: 0.3, security: 0.4 },
  securityPenalties: { critical: 40, high: 20, medium: 8, low: 3 },
  confidenceMultiplier: { high: 1.0, medium: 0.5, low: 0.2 },
  rugPullPenalty: 15,
  capScore: 49,
  bands: { brightgreen: 85, green: 70, yellow: 50, red: 30 },
};

export function securityScore(findings: Finding[], cfg: ScoringConfig = DEFAULT_SCORING): number {
  let score = 100;
  for (const f of findings) score -= cfg.securityPenalties[f.severity] * cfg.confidenceMultiplier[f.confidence];
  return clamp(score);
}

export function hasHardFail(findings: Finding[]): boolean {
  return findings.some((f) => f.confidence === "high" && (f.severity === "critical" || f.severity === "high"));
}

export function assemble(
  parts: { functional: FunctionalOutcome; conformance: ConformanceOutcome; security: SecurityOutcome },
  cfg: ScoringConfig = DEFAULT_SCORING,
): Report {
  const active: Array<{ weight: number; score: number }> = [];
  if (parts.functional.ran && parts.functional.score !== null)
    active.push({ weight: cfg.weights.functional, score: parts.functional.score });
  if (parts.conformance.ran && parts.conformance.score !== null)
    active.push({ weight: cfg.weights.conformance, score: parts.conformance.score });
  if (parts.security.ran && parts.security.score !== null)
    active.push({ weight: cfg.weights.security, score: parts.security.score });

  const totalWeight = active.reduce((s, a) => s + a.weight, 0) || 1;
  let score = Math.round(active.reduce((s, a) => s + (a.weight / totalWeight) * a.score, 0));

  if (parts.functional.drift?.descriptionOnly.length) score = clamp(score - cfg.rugPullPenalty);

  const capped = parts.security.ran && hasHardFail(parts.security.findings);
  if (capped) score = Math.min(score, cfg.capScore);

  const allFunctionalPassed = parts.functional.ran ? parts.functional.passed === parts.functional.total : true;
  const verdict: "PASS" | "FAIL" = !capped && allFunctionalPassed && score >= cfg.bands.yellow ? "PASS" : "FAIL";

  return {
    verdict,
    score,
    capped,
    functional: parts.functional,
    conformance: parts.conformance,
    security: parts.security,
    weights: cfg.weights,
  };
}

export function bandColor(score: number, failed: boolean, cfg: ScoringConfig = DEFAULT_SCORING): string {
  if (failed || score < cfg.bands.red) return "red";
  if (score >= cfg.bands.brightgreen) return "brightgreen";
  if (score >= cfg.bands.green) return "green";
  if (score >= cfg.bands.yellow) return "yellow";
  return "orange";
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, n));
}
