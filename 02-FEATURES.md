# 02 — Every Feature

Legend: ⭐ = MVP (v1, build now) · ⏭️ = deferred (v2+).

## A. Connection & discovery
1. ⭐ **Connect via stdio** — `--stdio "node server.js"` (local process servers).
2. ⭐ **Connect via Streamable HTTP** — `--http https://host/mcp` (remote servers). (Skip legacy SSE.)
3. ⭐ **Full capability enumeration** — list tools/resources/prompts with **pagination loop** (don't trust one page).
4. ⏭️ **FastMCP in-memory mode** — fast in-process testing of the author's own Python server.

## B. Functional / regression testing
5. ⭐ **YAML test specs** — call a tool/resource/prompt, assert: `exact`, `contains`, `json_schema` (Ajv), `tool_count`, `is_error`/`not_error`.
6. ⭐ **Env interpolation** in specs (`${MCP_TEST_API_KEY}`).
7. ⭐ **Schema-snapshot regression** — hash tool/resource/prompt schemas **+ descriptions**; fail PR on drift (added/removed/changed). The description-hash also flags **rug-pull / tool-poisoning** silently-changed descriptions.
8. ⏭️ `latency_ms` assertions / basic load smoke test.

## C. Conformance
9. ⭐ **Wrap the official `@modelcontextprotocol/conformance` CLI** — run server-mode, parse `checks.json`, fold into the verdict. Never reinvent.
10. ⭐ **Baseline support** — `conformance-baseline.yml` for known/accepted failures; fail only on **regressions** (un-baselined fails) or stale entries.
11. ⏭️ Conformance **client** mode (for MCP clients, not servers).

## D. Security — OWASP MCP Top 10 (detail in `04-SECURITY-OWASP.md`)
12. ⭐ **MCP04 dependency CVEs** — OSV.dev batch query (npm/PyPI). *High confidence.*
13. ⭐ **MCP01 secret exposure** — pattern + entropy + key-name proximity over manifest/descriptions/code; flag secrets returned in tool outputs.
14. ⭐ **MCP03(a) tool poisoning — invisible Unicode** — zero-width/bidi/tag chars in descriptions/schemas. *Near-zero false positives.*
15. ⭐ **MCP05 command injection** — static taint hint + **behavioral canary probe** (inject `$(echo MARKER)`, detect marker in output).
16. ⭐ **MCP07 missing auth** (HTTP) — connect unauthenticated; expect 401 + RFC 9728 `WWW-Authenticate`; check `/.well-known/oauth-protected-resource`.
17. ⏭️ **MCP02/06/08/09/10** — scope creep, intent subversion, audit gaps, shadowing, context over-sharing → heuristic/probe, shipped as lower-confidence `recommendation`/`note` (gated so they never hard-FAIL).
18. ⏭️ **AST taint engine** (replace the v1 static hint with real reachability analysis).
19. ⏭️ **LLM/embedding classifier** for injection-phrasing (MCP03b) — opt-in to avoid FP noise.
20. ⏭️ **Secret verification** (live API call to confirm a secret is active) — opt-in (privacy-sensitive).
21. ⏭️ **`--engine mcp-scan`** — optional plug-in to Invariant/Snyk's scanner for extra poisoning/shadow coverage.

## E. Output & integration
22. ⭐ **PASS/FAIL + 0–100 safety score** with the open scoring formula + security cap.
23. ⭐ **SARIF 2.1.0** output → GitHub code-scanning (Security tab) via `upload-sarif`.
24. ⭐ **`merit.json`** machine-readable full report (every finding + its score contribution).
25. ⭐ **GitHub Action** (composite) — runs the CLI, uploads SARIF, gates on `--min-score`/`--fail-on`.
26. ⭐ **PR comment** — one sticky, upserted comment with the verdict table + top findings.
27. ⭐ **shields.io endpoint badge** — JSON endpoint + README markdown.
28. ⏭️ Hosted org dashboard (history, trends, regression alerts, SSO) — the paid tier.
29. ⏭️ Public "verified servers" leaderboard/registry (marketing surface).

## F. DX
30. ⭐ **`meritmcp init`** — scaffold a starter `merit.tests.yaml` + snapshot.
31. ⭐ **`meritmcp snapshot`** — (re)capture the schema baseline.
32. ⭐ **Clean console UX** — the "8-second red FAIL → fix → green PASS" magic moment.
33. ⏭️ Config file (`meritmcp.config.json`) for advanced setups.

## MVP boundary (v1 = ship this)
All ⭐ items: stdio + HTTP connect → YAML functional tests + schema-drift → wrap conformance → 5 high-confidence security checks (MCP04/01/03a/05/07) → score + PASS/FAIL → SARIF + Action + PR comment + badge → `init`/`snapshot`. Plus fixtures: one clean server + one deliberately-vulnerable server (for demos + tests).
