// Parse + validate the YAML functional spec with zod, so a malformed test file
// fails loudly with a clear message instead of throwing deep in the runner.
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const AssertSchema = z.object({
  not_error: z.boolean().optional(),
  is_error: z.boolean().optional(),
  content_contains: z.string().optional(),
  content_matches: z.string().optional(),
  error_contains: z.string().optional(),
  tool_count: z.number().optional(),
  contains_tools: z.array(z.string()).optional(),
  structured: z.object({ json_schema: z.record(z.any()).optional() }).optional(),
});

const TestSchema = z.object({
  name: z.string(),
  op: z.enum(["list_tools", "call_tool"]),
  tool: z.string().optional(),
  arguments: z.record(z.any()).optional(),
  assert: AssertSchema,
});

const TargetSchema = z
  .object({
    transport: z.enum(["stdio", "http"]).optional(),
    command: z.string().optional(),
    url: z.string().optional(),
    env: z.record(z.string()).optional(),
  })
  .optional();

const TestFileSchema = z.object({
  version: z.literal(1).optional(),
  target: TargetSchema,
  tests: z.array(TestSchema),
});

export type TestFile = z.infer<typeof TestFileSchema>;
export type TestCase = z.infer<typeof TestSchema>;

export function loadTests(path: string): TestFile {
  const raw = parseYaml(readFileSync(path, "utf8"));
  const parsed = TestFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`invalid test file ${path}: ${parsed.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}`);
  }
  return parsed.data;
}
