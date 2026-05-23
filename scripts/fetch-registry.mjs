// Fetch the official MCP registry and write scripts/servers.json — npm packages launchable
// over stdio with NO required env vars/keys (so they can be scanned unconfigured) and no
// required positional args. Built for the exposé, which runs in a disposable CI sandbox.
//   node scripts/fetch-registry.mjs --limit=100
import { writeFileSync } from "node:fs";

const LIMIT = Number(process.argv.find((a) => a.startsWith("--limit="))?.split("=")[1] ?? 100);
const BASE = "https://registry.modelcontextprotocol.io/v0/servers";

const out = [];
const seen = new Set();
let cursor = "";
let pages = 0;

while (out.length < LIMIT && pages < 80) {
  const res = await fetch(`${BASE}?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
  if (!res.ok) break;
  const data = await res.json();
  pages++;
  for (const it of data.servers ?? []) {
    const srv = it.server ?? it;
    const pkgs = srv.packages ?? [];
    const npm = pkgs.find(
      (p) => (p.registryType ?? p.registry_type ?? p.registry_name) === "npm" && (p.transport?.type ?? "stdio") === "stdio",
    );
    if (!npm) continue;
    const id = npm.identifier ?? npm.name;
    if (!id || seen.has(id)) continue;
    const envs = npm.environmentVariables ?? npm.environment_variables ?? [];
    if (envs.some((e) => e.isRequired ?? e.is_required ?? e.required)) continue; // needs a key → can't launch
    const args = [...(npm.packageArguments ?? npm.package_arguments ?? []), ...(npm.runtimeArguments ?? npm.runtime_arguments ?? [])];
    if (args.some((a) => a.isRequired ?? a.is_required ?? a.required)) continue; // needs args we can't guess
    seen.add(id);
    out.push({ name: srv.name ?? id, command: `npx -y ${npm.version ? `${id}@${npm.version}` : id}` });
    if (out.length >= LIMIT) break;
  }
  cursor = data.metadata?.nextCursor ?? data.metadata?.next_cursor ?? "";
  if (!cursor) break;
}

writeFileSync(new URL("./servers.json", import.meta.url), JSON.stringify(out, null, 2));
console.log(`wrote ${out.length} keyless npm/stdio servers to scripts/servers.json (scanned ${pages} registry page(s))`);
