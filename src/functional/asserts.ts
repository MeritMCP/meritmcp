// Assertion primitives for the functional runner. Ajv powers the structured-output
// schema checks. Everything returns a list of human-readable failures (empty = pass).
import { Ajv } from "ajv";
import { createRequire } from "node:module";

// ajv-formats is CJS with an ESM-style .d.ts, which trips NodeNext's default-import
// typing. createRequire returns the real callable and types cleanly.
const require = createRequire(import.meta.url);
const addFormats = require("ajv-formats") as (ajv: Ajv, opts?: unknown) => void;

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

export interface AssertSpec {
  not_error?: boolean;
  is_error?: boolean;
  content_contains?: string;
  content_matches?: string; // regex source
  error_contains?: string;
  tool_count?: number;
  contains_tools?: string[];
  structured?: { json_schema?: object };
}

export interface CallContext {
  text: string;
  isError: boolean;
  structured?: unknown;
}

export interface CatalogContext {
  toolNames: string[];
}

export function assertCall(spec: AssertSpec, ctx: CallContext): string[] {
  const fails: string[] = [];
  if (spec.not_error && ctx.isError) fails.push("expected success but the tool returned isError=true");
  if (spec.is_error && !ctx.isError) fails.push("expected a tool error but the call succeeded");
  if (spec.content_contains !== undefined && !ctx.text.includes(spec.content_contains))
    fails.push(`output missing "${spec.content_contains}" (got "${trunc(ctx.text)}")`);
  if (spec.content_matches !== undefined && !new RegExp(spec.content_matches).test(ctx.text))
    fails.push(`output did not match /${spec.content_matches}/`);
  if (spec.error_contains !== undefined && !ctx.text.includes(spec.error_contains))
    fails.push(`error text missing "${spec.error_contains}"`);
  if (spec.structured?.json_schema) {
    const validate = ajv.compile(spec.structured.json_schema);
    if (!validate(ctx.structured ?? null))
      fails.push(`structured output failed schema: ${ajv.errorsText(validate.errors)}`);
  }
  return fails;
}

export function assertCatalog(spec: AssertSpec, ctx: CatalogContext): string[] {
  const fails: string[] = [];
  if (spec.tool_count !== undefined && ctx.toolNames.length !== spec.tool_count)
    fails.push(`expected ${spec.tool_count} tools, found ${ctx.toolNames.length}`);
  for (const t of spec.contains_tools ?? [])
    if (!ctx.toolNames.includes(t)) fails.push(`missing expected tool "${t}"`);
  return fails;
}

function trunc(s: string): string {
  return s.length > 80 ? `${s.slice(0, 77)}...` : s;
}
