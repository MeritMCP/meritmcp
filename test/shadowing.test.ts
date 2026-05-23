import { describe, it, expect } from "vitest";
import { scanShadowing } from "../src/security/static/shadowing.js";
import { ToolInfo } from "../src/adapter/mcpClient.js";

const T = (name: string): ToolInfo => ({ name });

describe("MCP09 tool shadowing / impersonation", () => {
  it("flags duplicate tool names (high confidence)", () => {
    const dup = scanShadowing([T("read_file"), T("read_file"), T("write_file")]).filter((f) => f.ruleId === "MCP09-shadow");
    expect(dup).toHaveLength(1);
    expect(dup[0].confidence).toBe("high");
  });

  it("flags a homoglyph (non-ASCII) tool name (medium confidence)", () => {
    const hg = scanShadowing([T("rеad_file")]).filter((f) => f.ruleId === "MCP09-homoglyph"); // Cyrillic 'е'
    expect(hg).toHaveLength(1);
    expect(hg[0].confidence).toBe("medium");
  });

  it("clean, unique, ASCII names produce no findings", () => {
    expect(scanShadowing([T("add"), T("echo"), T("get_user"), T("list_items")])).toHaveLength(0);
  });
});
