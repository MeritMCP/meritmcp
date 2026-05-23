// Runs the YAML functional tests against a connected server.
import { McpClient } from "../adapter/mcpClient.js";
import { loadTests } from "./parsers.js";
import { assertCall, assertCatalog } from "./asserts.js";
import { TestResult } from "../types.js";

export async function runFunctional(client: McpClient, testsPath: string): Promise<TestResult[]> {
  const file = loadTests(testsPath);
  const results: TestResult[] = [];
  const toolNames = (await client.listTools()).map((t) => t.name);

  for (const tc of file.tests) {
    try {
      if (tc.op === "list_tools") {
        const fails = assertCatalog(tc.assert, { toolNames });
        results.push({ name: tc.name, passed: fails.length === 0, detail: fails.join("; ") || "ok" });
      } else {
        if (!tc.tool) throw new Error("call_tool requires a 'tool' field");
        const res = await client.callTool(tc.tool, tc.arguments ?? {});
        const fails = assertCall(tc.assert, { text: res.text, isError: res.isError, structured: res.structured });
        results.push({ name: tc.name, passed: fails.length === 0, detail: fails.join("; ") || "ok" });
      }
    } catch (e) {
      results.push({ name: tc.name, passed: false, detail: `runtime error: ${(e as Error).message}` });
    }
  }
  return results;
}
