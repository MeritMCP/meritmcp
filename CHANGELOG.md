# Changelog

## 0.1.5
- **New security checks (static, always on):**
  - **MCP02 — misleading tool annotations** (`MCP02-scope`): flags a mutating/destructive tool that falsely claims `readOnlyHint: true`, so clients can't warn the user before it changes state.
  - **MCP09 — tool shadowing & homoglyphs** (`MCP09-shadow` / `MCP09-homoglyph`): flags duplicate tool names (impersonation) and non-ASCII look-alike characters in tool names.
- **Deeper secret detection (MCP01):** added GitHub fine-grained PATs, Slack webhook URLs, Stripe `rk_live`, npm tokens, Azure storage `AccountKey`, PEM private keys (critical), GCP service-account JSON, and JWTs — each with its own severity + confidence; still structured-format-only (no entropy guessing).
- **Hardened accuracy:** comprehensive true-positive **and** anti-false-positive test suites for every security check (secrets across 12 formats, unicode, shadowing, privilege).
- **Internal test coverage:** unit tests for the report layer (SARIF 2.1.0, shields badge bands, sticky PR comment) and for capability/transport-aware conformance scenario gating. **53 tests total.**
- Docs: full per-check reference table (detection method + confidence) in the README.

## 0.1.4
- **MCP01 secrets: removed the generic high-entropy heuristic** (kept only structured formats: AWS/GitHub/OpenAI-style/Google/Slack/Stripe). The heuristic false-positived on ordinary identifiers in tool metadata (e.g. a tool named `monarch_login_with_token`); a security scanner must not cry wolf. Real, recognizable keys are still flagged.

## 0.1.3
- `merit --version` and the SARIF report version now read the real package version (was hard-coded).

## 0.1.2 — first published release
The CI quality gate for MCP servers, in one command:
- **Functional** — YAML tool-call tests + schema-snapshot drift (incl. description-only "rug-pull" detection).
- **Conformance** — the **official** MCP conformance suite, capability- & transport-aware, run through an in-process stdio→HTTP proxy. Fetched on demand via `npx` (not bundled), so Merit's own install stays small.
- **Security (OWASP-MCP-Top-10)** — static checks always on (MCP01 secrets, MCP03a invisible-Unicode poisoning, MCP04 dependency CVEs via OSV.dev); live probes (MCP05 command-injection, MCP07 auth) are **opt-in** via `--probe`, and only flag genuine OS-shell execution.
- Emits a PASS/FAIL verdict + an open, reproducible 0–100 safety score, SARIF 2.1.0 (GitHub code scanning), a shields badge, and a sticky PR comment. Ships a composite GitHub Action.

_(0.1.0–0.1.1 were unpublished pre-releases.)_
