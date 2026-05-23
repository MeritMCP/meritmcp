# Merit

> **The CI quality gate for MCP servers** — one command that runs functional tests, the official MCP conformance suite, and OWASP-MCP-Top-10 security checks, then emits a PASS/FAIL verdict, a 0–100 safety score, SARIF for GitHub code scanning, and a README badge.

[![Merit](https://img.shields.io/badge/Merit-100%2F100%20·%20passing-brightgreen)](https://github.com/meritmcp/meritmcp)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

> ⚠️ **Status: alpha (0.1.x).** Wraps two fast-moving upstreams (`@modelcontextprotocol/sdk`, `@modelcontextprotocol/conformance`) which are pinned and isolated behind adapters. APIs may change before 1.0.

---

## Why

MCP servers are shipped fast and "vibe-tested." There's no standard way to answer, in one shot: *is my server functionally correct, spec-conformant, and not leaking secrets or running shell input?* Merit is that one shot — and the bundle is the point: **conformance ≠ correct ≠ secure.** A server can pass the official conformance suite while returning wrong answers and exposing a command-injection tool.

## Quickstart

```bash
# Point it at a stdio server…
npx meritmcp run --stdio "node dist/server.js"

# …or a Streamable HTTP server
npx meritmcp run --http https://your-host/mcp
```

You'll get a verdict like:

```
Merit — PASS · Safety score 93/100

Functional: 12/12 passed
Conformance: 8/8 applicable scenarios passed (score 100/100) · 22 N/A skipped
Security: 1 medium (score 96/100)
  ▲ [MCP07:2025] Server accepted an unauthenticated MCP session …
```

Exit code is `0` on PASS, `1` on FAIL (gate your CI), `2` on a setup error.

## What it checks

| Engine | What | Weight |
|---|---|---|
| **Functional** | Your YAML tests (tool calls + assertions) **and** schema-snapshot drift, incl. description-only "rug-pull" detection | 30% |
| **Conformance** | The **official** MCP conformance suite, wrapped — never reimplemented. Capability- & transport-aware so a tools-only server isn't punished for unimplemented optional features | 30% |
| **Security** | OWASP-MCP-Top-10. Static (always on): MCP01 secrets · MCP03a invisible-Unicode poisoning · MCP04 dependency CVEs via [OSV.dev](https://osv.dev). Live probes (**opt-in `--probe`**, only on a server you control): MCP05 command-injection · MCP07 HTTP auth | 40% |

> The conformance suite is HTTP-only. For stdio servers, Merit transparently spins up an in-process stdio→HTTP proxy so the official suite can test them. The suite is **not bundled** — it's fetched on demand via `npx` (keeping Merit's own install tiny); for fully-offline runs, install `@modelcontextprotocol/conformance` yourself, or pass `--no-conformance`.

## CLI

```bash
meritmcp run --stdio "<command>" | --http <url>  [options]
  --tests <path>                 YAML functional spec (default: merit.tests.yaml)
  --snapshot <path>              schema snapshot file (default: merit.snapshot.json)
  --src <dir>                    server source dir → enables dependency CVE scanning (OSV)
  --conformance-baseline <path>  YAML of expected conformance failures
  --min-score <n>                fail if the score is below n
  --sarif <path>                 write SARIF 2.1.0 (GitHub code scanning)
  --out <path>                   write the full report JSON (open, reproducible scoring)
  --badge <path>                 write a shields.io endpoint badge JSON
  --pr-comment <path>            write the PR-comment markdown
  --probe                        run LIVE security probes (side effects! only on servers you control)
  --no-security | --no-conformance
  --json                         print the raw report JSON

meritmcp snapshot --stdio "<command>" --out merit.snapshot.json   # capture/refresh the tool surface
meritmcp init                                                          # write a starter merit.tests.yaml
```

### Functional test spec (`merit.tests.yaml`)

```yaml
version: 1
tests:
  - name: "tool catalog is stable"
    op: list_tools
    assert:
      contains_tools: [search, fetch]
  - name: "add returns the sum"
    op: call_tool
    tool: add
    arguments: { a: 2, b: 3 }
    assert:
      not_error: true
      content_contains: "5"
      structured:
        json_schema: { type: object, required: [sum], properties: { sum: { const: 5 } } }
```

## GitHub Action

```yaml
# .github/workflows/meritmcp.yml
name: Merit
on: [pull_request]
permissions:
  contents: read
  security-events: write   # upload SARIF
  pull-requests: write     # sticky PR comment
jobs:
  meritmcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - uses: meritmcp/meritmcp@v0          # or: meritmcp/meritmcp@<sha>
        with:
          command: "node dist/server.js"      # or: url: https://your-host/mcp
          src: "."                            # enable dependency CVE scanning
          min-score: "70"
```

The Action runs Merit, uploads SARIF to the **Security** tab, and posts a sticky PR comment with the verdict. Outputs: `score`, `verdict`.

## The badge

`meritmcp run … --badge badge.json` writes a [shields.io endpoint](https://shields.io/endpoint) file. Publish it (gh-pages / a Gist) and embed:

```markdown
![Merit](https://img.shields.io/endpoint?url=https://<you>.github.io/<repo>/badge.json)
```

## Scoring (open + reproducible)

```
score = 0.30·functional + 0.30·conformance + 0.40·security
```

- Engines that don't run have their weight redistributed across the rest.
- **Security cap:** any *high-confidence* Critical/High finding caps the total at **49 and forces FAIL** — a pretty score can't hide a real hole.
- A description-only schema change (rug-pull) costs 15 points.
- Every weight lives in [`config/scoring.config.json`](./config/scoring.config.json) and every finding's contribution is in `merit.json`, so anyone can recompute the score by hand.

Low-confidence/heuristic findings are reported as notes — they never hard-FAIL. Detection methodology and confidence per OWASP risk: [`04-SECURITY-OWASP.md`](./04-SECURITY-OWASP.md).

## Development

```bash
npm install
npm run demo:pass    # green PASS against a clean fixture
npm run demo:fail    # red FAIL against a deliberately broken+insecure fixture
npm test             # unit tests
```

Design docs: [`01-DESIGN.md`](./01-DESIGN.md) · [`03-ARCHITECTURE.md`](./03-ARCHITECTURE.md) · [`04-SECURITY-OWASP.md`](./04-SECURITY-OWASP.md).

## License

[MIT](./LICENSE)
