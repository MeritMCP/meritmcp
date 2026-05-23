# 01 — Product Design (how it works)

## The promise
A server author runs **one command** (or adds **one GitHub Action**) and gets a single, trustworthy verdict: *is my MCP server functionally correct, spec-conformant, and secure enough to publish?* — plus a badge that signals that trust to everyone who installs their server.

## The core flow
```
1. POINT    meritmcp at a server:  --stdio "node server.js"   OR   --http https://host/mcp
2. CONNECT  the tool connects via the official MCP SDK, enumerates tools/resources/prompts (paginated)
3. RUN      three engines in parallel:
              • FUNCTIONAL  — your YAML tests + schema-snapshot drift check
              • CONFORMANCE — wraps the official MCP conformance CLI
              • SECURITY    — OWASP-MCP-Top-10 (static + behavioral probes) + OSV dep scan
4. SCORE    compute a 0–100 safety score (open formula) + PASS/FAIL (security cap)
5. EMIT     console verdict · SARIF (→ GitHub Security tab) · PR comment · badge JSON
```

## The three things it checks (and why each matters)
1. **Functional / regression** — does each tool actually return what it should, and did the tool schemas silently change (drift)? *Solves the "vibe-tested, broke in prod, CI couldn't catch the schema change" pain.*
2. **Conformance** — does it obey the MCP spec (lifecycle, capability negotiation, error handling)? *We wrap the official suite — canonical, never reinvented.*
3. **Security** — OWASP-MCP-Top-10: leaked secrets, command injection, tool poisoning (hidden/invisible-Unicode instructions), vulnerable deps, missing auth, etc. *The loud hook — 66% of servers fail something.*

## The verdict (what the user sees)

**Console / PR comment:**
```
Merit — PASS · Safety score 87/100
┌────────────┬───────────────────────┬────────┐
│ Functional │ 12/12 passed          │  30%   │
│ Conformance│ 41/43 (2 baselined)   │  30%   │
│ Security   │ 0 high · 2 medium     │  40%   │
│ Schema     │ no drift              │   —    │
└────────────┴───────────────────────┴────────┘
Top findings: MCP01 secret (medium, db.ts:10) · MCP02 scope (low)
→ Full results in the GitHub Security tab (SARIF).
```

**The badge** (README): `![Merit](https://img.shields.io/endpoint?url=…/merit-badge.json)` → renders **"Merit: 87/100 · passing"** (color-banded: ≥85 bright-green, 70–84 green, 50–69 yellow, <30 red; any hard-FAIL = red).

## The scoring model (open + reproducible — this is what makes the badge trustworthy)
```
Score = 0.30·Functional + 0.30·Conformance + 0.40·Security
```
- **Functional** = 100 × passed/total (if no tests defined, weight redistributes to Conf/Sec).
- **Conformance** = 100 × passed/(total − baselined).
- **Security** = starts at 100; subtract per finding × confidence (high 1.0 / medium 0.5 / low 0.2): Critical −40, High −20, Medium −8, Low −3. Schema rug-pull (description-only change) −15.
- **🔒 Security cap (integrity rule):** any *high-confidence* Critical/High security finding caps the total at **49 and forces FAIL** — no matter how good functional/conformance are. This is what stops a pretty score from hiding a real hole.
- All weights live in a committed `scoring.config.json`; every finding + its point contribution is logged to `merit.json` so anyone can recompute by hand. **Open methodology = the only way a self-issued score earns trust.**

## User flows
- **Local dev:** `npx meritmcp --stdio "node dist/server.js" --src ./src` → instant verdict before pushing.
- **CI (the sticky use):** add the Action → every PR gets the verdict as a comment + SARIF in the Security tab + a build gate (`--min-score`, `--fail-on`).
- **Publish:** drop the badge in your README → consumers see the trust signal.
- **The exposé (GTM):** run it across the top-200 registry servers → publish the leaderboard.

## Design principles
- **One command, one verdict.** No four-tool stitching.
- **Trustworthy over scary** — honest confidence levels; low-confidence findings can't tank a score or hard-FAIL (avoids the "regex-only scanner cries wolf" death).
- **The bundle IS the product (the CI quality gate):** functional + schema-drift + conformance + security + one score. Security is the **loud marketing hook**, not the whole product — pure security scanning is a red ocean (Ramparts, Snyk agent-scan, Cisco, Enkrypt, mcpscan.ai); almost none of them do functional + conformance, and that's our moat.
- **Local-first, no account** (the anti-Snyk wedge). DX-obsessed.
