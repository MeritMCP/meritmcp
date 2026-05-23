// Capture a hash snapshot of a server's tool surface so drift is a cheap diff later.
// Each tool gets two hashes: `hash` (full, incl. description) and `shash` (structural,
// description excluded) — so a description-only change can be flagged as a rug-pull.
import { ToolInfo } from "../adapter/mcpClient.js";
import { canonicalHash } from "./canonicalize.js";

export interface ToolSnapshot {
  hash: string;
  shash: string;
}

export interface Snapshot {
  version: 1;
  createdAt: string;
  rootHash: string;
  tools: Record<string, ToolSnapshot>;
}

export function capture(tools: ToolInfo[]): Snapshot {
  const entries: Record<string, ToolSnapshot> = {};
  for (const t of tools) {
    entries[t.name] = {
      hash: canonicalHash({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
        outputSchema: t.outputSchema,
        annotations: t.annotations,
      }),
      shash: canonicalHash({
        name: t.name,
        inputSchema: t.inputSchema,
        outputSchema: t.outputSchema,
        annotations: t.annotations,
      }),
    };
  }
  const rootHash = canonicalHash(
    Object.keys(entries)
      .sort()
      .map((n) => [n, entries[n].hash]),
  );
  return { version: 1, createdAt: new Date().toISOString(), rootHash, tools: entries };
}
