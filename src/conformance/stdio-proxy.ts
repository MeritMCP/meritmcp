// stdio→HTTP proxy. The official conformance suite is HTTP-only (--url, no --stdio),
// so to test a stdio server we expose it over Streamable HTTP here. This is a transparent
// JSON-RPC relay: an HTTP server transport (facing conformance) bridged to a fresh stdio
// child per session (the server-under-test). Messages are forwarded verbatim — no parsing.
import { createServer, IncomingMessage, ServerResponse, Server } from "node:http";
import { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { splitCommand, currentEnv } from "../adapter/mcpClient.js";

export interface ProxyHandle {
  url: string;
  close: () => Promise<void>;
}

interface Session {
  http: StreamableHTTPServerTransport;
  close: () => Promise<void>;
}

export async function startStdioHttpProxy(commandString: string, path = "/mcp"): Promise<ProxyHandle> {
  const { command, args } = splitCommand(commandString);
  const env = currentEnv();
  const sessions = new Map<string, Session>();

  async function newSession(): Promise<StreamableHTTPServerTransport> {
    const child = new StdioClientTransport({ command, args, env });
    const http: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid: string) => {
        sessions.set(sid, { http, close });
      },
    });

    // Idempotent teardown — both transports' onclose route here, and so does proxy.close(),
    // so the underlying handles are only closed once (avoids libuv double-close on Windows).
    let closed = false;
    async function close(): Promise<void> {
      if (closed) return;
      closed = true;
      await http.close().catch(() => {});
      await child.close().catch(() => {});
    }

    // Transparent bidirectional relay (verbatim JSON-RPC).
    http.onmessage = (msg) => void child.send(msg).catch(() => {});
    child.onmessage = (msg) => void http.send(msg).catch(() => {});
    http.onclose = () => void close();
    child.onclose = () => void close();
    await child.start();
    await http.start();
    return http;
  }

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      if (!req.url || !req.url.startsWith(path)) {
        res.statusCode = 404;
        res.end();
        return;
      }
      const sid = req.headers["mcp-session-id"] as string | undefined;
      let transport = sid ? sessions.get(sid)?.http : undefined;
      const body = await readBody(req);

      if (!transport) {
        if (isInitialize(body)) {
          transport = await newSession();
        } else {
          res.statusCode = 400;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "No valid session" }, id: null }));
          return;
        }
      }
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end();
      }
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}${path}`,
    close: async () => {
      for (const s of sessions.values()) await s.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function isInitialize(body: unknown): boolean {
  const first = Array.isArray(body) ? body[0] : body;
  return Boolean(first) && typeof first === "object" && (first as { method?: string }).method === "initialize";
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  if (req.method !== "POST") return undefined;
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}
