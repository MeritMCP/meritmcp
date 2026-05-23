# Changelog

## 0.1.3
- `merit --version` and the SARIF report version now read the real package version (was hard-coded).

## 0.1.2 — first published release
The CI quality gate for MCP servers, in one command:
- **Functional** — YAML tool-call tests + schema-snapshot drift (incl. description-only "rug-pull" detection).
- **Conformance** — the **official** MCP conformance suite, capability- & transport-aware, run through an in-process stdio→HTTP proxy. Fetched on demand via `npx` (not bundled), so Merit's own install stays small.
- **Security (OWASP-MCP-Top-10)** — static checks always on (MCP01 secrets, MCP03a invisible-Unicode poisoning, MCP04 dependency CVEs via OSV.dev); live probes (MCP05 command-injection, MCP07 auth) are **opt-in** via `--probe`, and only flag genuine OS-shell execution.
- Emits a PASS/FAIL verdict + an open, reproducible 0–100 safety score, SARIF 2.1.0 (GitHub code scanning), a shields badge, and a sticky PR comment. Ships a composite GitHub Action.

_(0.1.0–0.1.1 were unpublished pre-releases.)_
