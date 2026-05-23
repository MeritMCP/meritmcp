// THE single SDK chokepoint. Every @modelcontextprotocol/sdk call lives here so
// the coming v2 package split is a one-file migration (see 03-ARCHITECTURE.md).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

export interface ConnectOptions {
  transport: "stdio" | "http";
  command?: string; // full command string for stdio, e.g. 'node dist/server.js'
  url?: string; // endpoint for http
  env?: Record<string, string>;
}

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export interface CallResult {
  text: string;
  isError: boolean;
  structured?: unknown;
  raw: unknown;
}

export class McpClient {
  private client: Client;

  constructor(name = "merit", version = "0.1.0") {
    this.client = new Client({ name, version }, { capabilities: {} });
  }

  async connect(opts: ConnectOptions): Promise<void> {
    if (opts.transport === "http") {
      if (!opts.url) throw new Error('HTTP transport requires --http <url>');
      await this.client.connect(new StreamableHTTPClientTransport(new URL(opts.url)));
      return;
    }
    if (!opts.command) throw new Error('stdio transport requires --stdio "<command>"');
    const { command, args } = splitCommand(opts.command);
    await this.client.connect(
      new StdioClientTransport({ command, args, env: { ...currentEnv(), ...(opts.env ?? {}) } }),
    );
  }

  /** Enumerate all tools, following pagination cursors. */
  async listTools(): Promise<ToolInfo[]> {
    const out: ToolInfo[] = [];
    let cursor: string | undefined;
    do {
      const page = (await this.client.listTools(cursor ? { cursor } : undefined)) as {
        tools?: ToolInfo[];
        nextCursor?: string;
      };
      out.push(...(page.tools ?? []));
      cursor = page.nextCursor;
    } while (cursor);
    return out;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallResult> {
    const res = (await this.client.callTool({ name, arguments: args })) as {
      content?: Array<{ type: string; text?: string }>;
      isError?: boolean;
      structuredContent?: unknown;
    };
    const text = (res.content ?? [])
      .filter((c) => c.type === "text" && typeof c.text === "string")
      .map((c) => c.text as string)
      .join("\n");
    return { text, isError: Boolean(res.isError), structured: res.structuredContent, raw: res };
  }

  /** Server capabilities negotiated during initialize (available after connect). */
  serverCapabilities(): Record<string, unknown> {
    return (this.client.getServerCapabilities() ?? {}) as Record<string, unknown>;
  }

  async close(): Promise<void> {
    try {
      await this.client.close();
    } catch {
      /* server may already be gone; ignore */
    }
  }
}

/** Split a shell-ish command string into command + args, respecting quotes. */
export function splitCommand(cmd: string): { command: string; args: string[] } {
  const matches = cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
  const parts = matches.map((s) => s.replace(/^["']|["']$/g, ""));
  const [command, ...args] = parts;
  if (!command) throw new Error(`could not parse command: ${cmd}`);
  return { command, args };
}

/** process.env with undefined values dropped (StdioClientTransport wants Record<string,string>). */
export function currentEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (typeof v === "string") out[k] = v;
  return out;
}
