// CLEAN fixture: a small, correct, well-behaved MCP server. Merit should PASS it.
// Run standalone: npm run fixture:clean
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "clean-fixture", version: "1.0.0" });

// NOTE (Day-1 validation): confirm registerTool signature against the installed
// @modelcontextprotocol/sdk@1.29 — the 1.x high-level API is registerTool(name, config, cb).
server.registerTool(
  "add",
  {
    description: "Add two numbers and return their sum.",
    inputSchema: { a: z.number(), b: z.number() },
    outputSchema: { sum: z.number() },
  },
  async ({ a, b }) => {
    const sum = a + b;
    return { content: [{ type: "text", text: String(sum) }], structuredContent: { sum } };
  },
);

server.registerTool(
  "echo",
  {
    description: "Echo back the provided text.",
    inputSchema: { text: z.string() },
  },
  async ({ text }) => ({ content: [{ type: "text", text }] }),
);

await server.connect(new StdioServerTransport());
