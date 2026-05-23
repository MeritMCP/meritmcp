# 03 — Architecture (locked technical design)

> Build-ready. All external APIs named with current versions + sources. `[UNSTABLE]` = pin hard, isolate.

## Stack (locked)
- **Language:** **TypeScript on Node 20+.** Rationale: the official conformance suite + most mature MCP SDK are TS → one runtime, one toolchain, no language boundary; SARIF/Actions/shields are all trivially Node; single-language repo = lowest cognitive load for AI-agent-driven dev.
- **MCP client:** `@modelcontextprotocol/sdk@^1.29` **[UNSTABLE — v2 is splitting the package + changing import paths]** → **isolate ALL SDK calls behind one `adapter/mcpClient.ts`** so the v2 migration is a one-file change.
- **Conformance:** `@modelcontextprotocol/conformance@0.1.16` **[UNSTABLE — pre-1.0; `0.2.0-alpha.0` exists = package split coming]**, pinned, shelled out, isolated behind the wrapper.
- **Schema validation:** Ajv. **Canonical hashing:** `json-stable-stringify` (JCS/RFC 8785) + SHA-256.
- **Dep CVEs:** OSV.dev `POST /v1/querybatch`.
- **Output:** SARIF 2.1.0 → `github/codeql-action/upload-sarif@v3`; badge via shields.io endpoint + Schneegans dynamic-badges (or gh-pages JSON).
- **CLI:** commander/clipanion + zod config parsing. **Tests:** vitest.

## MCP client (the adapter)
```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const client = new Client({ name: "meritmcp", version: "1.0.0" }, { capabilities: {} });
const transport = isHttp
  ? new StreamableHTTPClientTransport(new URL(url))
  : new StdioClientTransport({ command, args, env });
await client.connect(transport);
// listTools / callTool / listResources / readResource / listPrompts / getPrompt (loop nextCursor)
```
Handle both tool-level errors (`result.isError`) and protocol throws. Paginate everything.

## Functional test spec (YAML)
```yaml
version: 1
target: { transport: stdio, command: "node dist/server.js", env: { API_KEY: ${MCP_TEST_API_KEY} } }
tests:
  - name: "tool catalog stable"
    op: list_tools
    assert: { tool_count: 5, contains_tools: [search, fetch] }
  - name: "add returns sum"
    op: call_tool
    tool: add
    arguments: { a: 2, b: 3 }
    assert:
      not_error: true
      content_contains: "5"
      structured: { json_schema: { type: object, required: [sum], properties: { sum: { const: 5 } } } }
```

## Schema-snapshot drift (`merit.snapshot.json`)
Enumerate all primitives → canonicalize (key-sort + stable stringify) → SHA-256 hash of `name + inputSchema + description + annotations + outputSchema` (per tool; analogous for resources/prompts) → `rootHash` for a one-line "anything changed?". Diff on each run: added(note) / removed(warn-breaking) / schema-changed(error-breaking) / **description-only-changed(warn + rug-pull flag to security)**. Commit the snapshot; CI fails on un-acknowledged drift.

## Conformance wrapper
Shell out (don't reimplement):
```bash
npx @modelcontextprotocol/conformance@0.1.16 server --url http://localhost:3000/mcp \
  --suite active --expected-failures ./conformance-baseline.yml -o ./results --verbose
```
Confirmed flags: `--url` (required), `--suite active|all|pending`, `--expected-failures <path>` (baseline), `-o/--output-dir`, `--verbose` (emits JSON). Parse the JSON output (array of pass/fail checks), not stdout. Baseline-aware exit codes (regression = fail not in baseline).

**🔧 CONFIRMED (was a prediction): conformance is HTTP-ONLY — there is no `--stdio`/`--command`; it only accepts `--url`.** So for stdio servers-under-test we **must build a thin stdio→HTTP proxy** (the SDK has both transports — launch the target as a stdio child, expose it on `http://localhost:<port>/mcp`, point conformance there). This is a required **MVP component**, not a "validate later" item.

## Security engine
Two sub-engines — **STATIC** (manifest/descriptions/code if `--src` given) and **PROBE** (live payloads). Every finding carries `confidence: high|medium|low` → SARIF `precision` + score multiplier. **Anti-FP doctrine: never regex-only** — corroborate (pattern + entropy + context, or taint reachability, or a confirming live probe). Detail per OWASP risk in `04-SECURITY-OWASP.md`. Dep CVEs via OSV `querybatch` (ecosystems `npm`/`PyPI`, order-preserving response).

## Output
- **SARIF 2.1.0:** one `run`; `tool.driver` with `rules[]` (id + shortDescription + `defaultConfiguration.level` + `properties.security-severity` 0.1–10.0 + `tags:[owasp-mcp, MCPxx:2025]`); `results[]` with `message.text` + `locations[]` + `partialFingerprints`. For probe-only findings with no source line, use a synthetic `artifactLocation.uri` like `mcp-server://tool/<name>`, region line 1.
- **GitHub Action:** composite — runs CLI → `upload-sarif@v3` → gate on `--min-score`/`--fail-on`.
- **PR comment:** upsert one sticky comment (actions/github-script).
- **Badge:** publish `{schemaVersion:1,label:"Merit",message:"87/100 · PASS",color:"brightgreen"}` to gh-pages/Gist; README uses shields endpoint URL.

## Component diagram
```
CLI / GitHub Action → Orchestrator (config, run order, gating)
   ├─ McpClientAdapter (SDK v1.x; stdio/http)   ← single SDK chokepoint
   ├─ Functional Runner (YAML + Ajv)
   ├─ Conformance Wrapper (spawn npx; parse checks.json)
   ├─ Security Engine (static + probe + OSV)
   └─ Snapshot/Drift (hash diff)
        → Findings model (typed) → SARIF · Scorer · PR comment · Badge · Console PASS/FAIL
```

## Repo structure
```
meritmcp/
  package.json            # bin: meritmcp
  action.yml              # composite GitHub Action
  src/
    cli.ts  orchestrator.ts
    adapter/mcpClient.ts          # ALL SDK calls here
    functional/{runner,parsers,asserts}.ts
    conformance/{wrapper.ts, stdio-proxy.ts}   # proxy = required (conformance is HTTP-only)
    security/{engine,owasp-map}.ts
      static/{secrets,unicode,deps-osv,taint,auth-meta}.ts
      probe/{injection,authz,oversharing}.ts
    snapshot/{capture,diff,canonicalize}.ts
    report/{sarif,badge,prcomment,score}.ts
  config/{scoring.config.json, rules.json}
  schemas/tests.schema.json
  fixtures/   # 1 clean server + 1 deliberately-vulnerable server
  test/
```

## Day-1 validation tasks (pre-1.0 APIs)
1. `npx @modelcontextprotocol/conformance@0.1.16 server --help` → confirm exact JSON output field names + output-dir layout.
2. Confirm SDK `@modelcontextprotocol/sdk@1.29.0` import paths + method signatures (1.29.0 is latest).
3. **Build the stdio→HTTP proxy** (required because conformance is HTTP-only) — validate against a stdio fixture server.
4. Build the two fixture servers (clean + vulnerable) — test harness AND demo.
*(Watch: conformance `0.2.0-alpha` = package split incoming; SDK v2 splitting packages. Both isolated behind wrappers/adapters → one-file migrations.)*
