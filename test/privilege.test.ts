import { describe, it, expect } from "vitest";
import { scanPrivilege } from "../src/security/static/privilege.js";
import { ToolInfo } from "../src/adapter/mcpClient.js";

describe("MCP02 privilege — misleading readOnlyHint", () => {
  it("flags readOnlyHint:true on a mutating/destructive tool", () => {
    const f = scanPrivilege([{ name: "delete_user", description: "remove a user", annotations: { readOnlyHint: true } }]);
    expect(f).toHaveLength(1);
    expect(f[0].ruleId).toBe("MCP02-scope");
  });

  it("does NOT flag an honest read-only tool", () => {
    expect(scanPrivilege([{ name: "get_user", description: "fetch a user", annotations: { readOnlyHint: true } }])).toHaveLength(0);
  });

  it("does NOT flag a mutating tool that doesn't falsely claim read-only", () => {
    expect(scanPrivilege([{ name: "delete_user", annotations: { destructiveHint: true } }])).toHaveLength(0);
    expect(scanPrivilege([{ name: "delete_user" }])).toHaveLength(0);
  });
});
