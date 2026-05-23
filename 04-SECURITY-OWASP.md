# 04 — Security: OWASP MCP Top 10 detection

> `[UNSTABLE]` OWASP MCP Top 10 is Beta v0.1 — IDs/order may shift. Tag every finding with the OWASP ID **and** our own stable rule ID so re-ordering never breaks consumers. **Doctrine: never regex-only.** Every static signal needs corroboration; every probe that gets a benign/refusal response is a PASS, not silence.

## Detection table

| OWASP | Engine | How we detect (concrete) | Reliability | MVP? |
|---|---|---|---|---|
| **MCP01 Token/secret exposure** | static + probe | provider regex (AWS `AKIA…`, `ghp_…`) **AND** Shannon entropy **AND** key-name proximity; flag secrets returned in tool outputs; opt-in live verification → `high` | **High** (known patterns) / med (generic) | ✅ |
| **MCP02 Privilege escalation / scope creep** | static | parse declared scopes + tool annotations (`readOnlyHint`/`destructiveHint`); flag mutating verbs (`delete/exec/write`) marked non-destructive, over-broad scopes | Medium (heuristic → `recommendation`, never hard-FAIL) | ⏭️ |
| **MCP03 Tool poisoning** | static | **(a)** invisible/abusable Unicode in descriptions/schemas (zero-width, bidi/RTL overrides, tag chars) — deterministic; **(b)** imperative-injection phrasing ("ignore previous", "don't tell the user") via classifier (opt-in) | **(a) High** (≈0 FP) / (b) medium | ✅ (a only) |
| **MCP04 Supply chain / deps** | static | parse lockfiles → **OSV.dev** `querybatch`; report CVE/GHSA + CVSS | **High** (authoritative) | ✅ |
| **MCP05 Command injection** | static + probe | static: taint hint (input param → `exec`/`eval`/`os.system`); **probe: canary** (`$(echo MCPV_$RAND)`, backticks) → detect marker in output | **High** when probe confirms / med static-only | ✅ |
| **MCP06 Intent-flow subversion** | static | MCP03(b) phrasing analysis on resource/prompt content that re-steers the agent | Low–med (`recommendation`) | ⏭️ |
| **MCP07 Insufficient auth/authz** | probe (HTTP) | connect with no/invalid token → expect **401 + RFC 9728 `WWW-Authenticate`**; fetch `/.well-known/oauth-protected-resource`; flag unauth tool calls that succeed | **High** (HTTP) / N/A (stdio) | ✅ |
| **MCP08 Audit/telemetry gap** | static | does server declare `logging` capability / emit log notifications? | Low (`note`) | ⏭️ |
| **MCP09 Shadow / impersonation** | static + probe | tool-name shadowing via Unicode-confusable normalization; TLS/cert posture (HTTP) | Medium | ⏭️ |
| **MCP10 Context injection / over-sharing** | probe | after benign call, inspect outputs for leaked secrets/PII/other-session data; indirect-injection via a tool input (URL/file the server fetches) → see if hidden instructions surface | Med (confirmed = `high`) | ⏭️ |

## Honest reliability summary
- **Reliably detectable (high confidence — MVP):** MCP04 (OSV deps), MCP01 (pattern + verified secrets), MCP03(a) invisible-Unicode, MCP05 (with confirming probe), MCP07 (HTTP auth), **schema-drift rug-pull** (from the snapshot module).
- **Heuristic only (ship as `recommendation`/`note`, never hard-FAIL, low score weight):** MCP02, MCP06, MCP08, and the LLM-phrasing half of MCP03/MCP10.
- **Not detectable from outside one server:** cross-server shadowing (MCP09 across registries) and post-approval rug-pulls — **except** via our description-hash drift check (which is exactly why we hash descriptions).

## Why this calibration matters (the death-avoidance rule)
Regex-only scanners get **publicly audited and dunked** (e.g., a respected dev opening the source and finding "a file full of regular expressions"). And high-false-positive scanners get abandoned ("cry wolf"). So:
- Low-confidence findings → SARIF `note`/`recommendation`, small/zero score weight, **cannot** trigger hard-FAIL.
- Only **high-confidence Critical/High** findings hit the security cap (total ≤49, FAIL).
- Methodology is **open + OWASP-aligned + reproducible** → ride OWASP's brand, not a self-issued black box.

## Reuse, don't reinvent
- **OSV.dev** for deps (don't build a vuln DB).
- Optional `--engine` plug-in to **Snyk agent-scan** (formerly Invariant mcp-scan) / **Ramparts** for extra poisoning/shadow detection later. (These are pure scanners — we integrate, not compete; our value is the bundle.)
- Map every rule to the **OWASP MCP Security Cheat Sheet** controls so findings link to canonical remediation.
