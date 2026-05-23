// Shared, typed models. The whole pipeline produces a single `Report`.

export type Confidence = "high" | "medium" | "low";
export type Severity = "critical" | "high" | "medium" | "low";

export interface TestResult {
  name: string;
  passed: boolean;
  detail: string;
}

export interface Finding {
  ruleId: string; // stable Merit rule id, e.g. "MCP01-secret"
  owasp?: string; // e.g. "MCP01:2025"
  severity: Severity;
  confidence: Confidence;
  message: string;
  location?: string; // file:line, or synthetic "mcp-server://tool/<name>"
}

export interface DriftSummary {
  hasSnapshot: boolean;
  changed: boolean;
  added: string[];
  removed: string[];
  schemaChanged: string[]; // breaking
  descriptionOnly: string[]; // rug-pull candidates (description changed, schema didn't)
}

export interface EngineOutcome {
  ran: boolean;
  score: number | null; // 0..100, null when the engine didn't run
}

export interface ConformanceScenario {
  scenario: string;
  passed: boolean;
  applicable: boolean; // counts toward the score (capability- and transport-aware)
  error?: string;
}

export interface ConformanceOutcome extends EngineOutcome {
  passed: number; // applicable scenarios passed
  total: number; // applicable scenarios
  rawPassed: number; // all scenarios passed
  rawTotal: number; // all scenarios run
  scenarios: ConformanceScenario[];
  note?: string;
}

export interface FunctionalOutcome extends EngineOutcome {
  passed: number;
  total: number;
  results: TestResult[];
  drift?: DriftSummary;
}

export interface SecurityOutcome extends EngineOutcome {
  findings: Finding[];
}

export interface Report {
  verdict: "PASS" | "FAIL";
  score: number; // 0..100
  capped: boolean; // true when a high-confidence Critical/High forced the cap
  functional: FunctionalOutcome;
  conformance: ConformanceOutcome;
  security: SecurityOutcome;
  weights: { functional: number; conformance: number; security: number };
}
