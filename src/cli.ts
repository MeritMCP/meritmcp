#!/usr/bin/env node
import { Command } from "commander";
import { writeFileSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { run } from "./orchestrator.js";
import { McpClient, ConnectOptions } from "./adapter/mcpClient.js";
import { capture } from "./snapshot/capture.js";
import { printReport } from "./report/console.js";
import { toSarif } from "./report/sarif.js";
import { toBadge } from "./report/badge.js";
import { toMarkdown } from "./report/prcomment.js";
import { DEFAULT_SCORING } from "./report/score.js";

const STARTER_TESTS = `version: 1
# Merit functional tests. Point the CLI at your server with --stdio / --http.
tests:
  - name: "tool catalog is stable"
    op: list_tools
    assert:
      contains_tools: []       # e.g. [search, fetch]
  # - name: "add returns the sum"
  #   op: call_tool
  #   tool: add
  #   arguments: { a: 2, b: 3 }
  #   assert:
  #     not_error: true
  #     content_contains: "5"
`;

// Read the real version from package.json (dist/src/cli.js → ../../package.json) so the
// CLI + SARIF report can never drift from the published version.
const VERSION: string = (() => {
  try {
    return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "package.json"), "utf8")).version;
  } catch {
    return "0.0.0";
  }
})();

const program = new Command();
program.name("merit").description("The CI quality gate for MCP servers").version(VERSION);

function connectOpts(opts: { stdio?: string; http?: string }): ConnectOptions {
  return opts.http ? { transport: "http", url: opts.http } : { transport: "stdio", command: opts.stdio };
}

program
  .command("run")
  .description("Connect to an MCP server and run the quality gate: functional tests + schema-drift + official conformance + OWASP-MCP-Top-10 security.")
  .option("--stdio <command>", 'launch a stdio MCP server, e.g. "node dist/server.js"')
  .option("--http <url>", "connect to a Streamable HTTP MCP server URL")
  .option("--tests <path>", "YAML functional test spec", "merit.tests.yaml")
  .option("--snapshot <path>", "schema snapshot file", "merit.snapshot.json")
  .option("--src <dir>", "server source dir (enables dependency CVE scanning via OSV)")
  .option("--no-security", "skip the OWASP-MCP-Top-10 security checks")
  .option("--probe", "run LIVE security probes — sends canary payloads to the server's tools (may trigger real tool actions; only use on a server you control). Off by default.", false)
  .option("--no-conformance", "skip the official MCP conformance suite")
  .option("--conformance-baseline <path>", "YAML of expected conformance failures (baseline)")
  .option("--min-score <n>", "fail if the score is below this", "0")
  .option("--sarif <path>", "write SARIF 2.1.0 (for GitHub code scanning)")
  .option("--out <path>", "write the full report JSON (open, reproducible scoring)")
  .option("--badge <path>", "write a shields.io endpoint badge JSON")
  .option("--pr-comment <path>", "write the PR-comment markdown")
  .option("--json", "print the raw report as JSON instead of the console verdict", false)
  .action(async (opts) => {
    if (!opts.stdio && !opts.http) {
      console.error('✖ provide --stdio "<command>" or --http <url>');
      process.exit(2);
    }
    try {
      const report = await run({
        connect: connectOpts(opts),
        testsPath: opts.tests,
        snapshotPath: opts.snapshot,
        srcDir: opts.src,
        security: opts.security,
        probe: opts.probe,
        conformance: opts.conformance,
        conformanceBaseline: opts.conformanceBaseline,
      });
      if (opts.sarif) writeFileSync(opts.sarif, JSON.stringify(toSarif(report, VERSION), null, 2));
      if (opts.badge) writeFileSync(opts.badge, JSON.stringify(toBadge(report), null, 2));
      if (opts.prComment) writeFileSync(opts.prComment, toMarkdown(report));
      if (opts.out) writeFileSync(opts.out, JSON.stringify({ ...report, scoring: DEFAULT_SCORING, generatedAt: new Date().toISOString() }, null, 2));

      if (opts.json) console.log(JSON.stringify(report, null, 2));
      else printReport(report);
      const ok = report.verdict === "PASS" && report.score >= Number(opts.minScore);
      process.exit(ok ? 0 : 1);
    } catch (e) {
      console.error(`✖ ${(e as Error).message}`);
      process.exit(2);
    }
  });

program
  .command("snapshot")
  .description("Capture/refresh the schema snapshot of a server's tool surface.")
  .option("--stdio <command>", "launch a stdio MCP server")
  .option("--http <url>", "connect to a Streamable HTTP MCP server URL")
  .option("--out <path>", "snapshot output file", "merit.snapshot.json")
  .action(async (opts) => {
    if (!opts.stdio && !opts.http) {
      console.error("✖ provide --stdio or --http");
      process.exit(2);
    }
    const client = new McpClient();
    try {
      await client.connect(connectOpts(opts));
      const snap = capture(await client.listTools());
      writeFileSync(opts.out, JSON.stringify(snap, null, 2));
      console.log(`✔ wrote ${opts.out} (rootHash ${snap.rootHash.slice(0, 12)}…, ${Object.keys(snap.tools).length} tools)`);
    } finally {
      await client.close();
    }
  });

program
  .command("init")
  .description("Write a starter merit.tests.yaml.")
  .option("--out <path>", "output path", "merit.tests.yaml")
  .action((opts) => {
    if (existsSync(opts.out)) {
      console.error(`✖ ${opts.out} already exists`);
      process.exit(1);
    }
    writeFileSync(opts.out, STARTER_TESTS);
    console.log(`✔ wrote ${opts.out} — edit it, then: merit run --stdio "node dist/server.js"`);
  });

program.parseAsync();
