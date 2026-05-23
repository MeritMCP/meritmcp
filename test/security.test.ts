import { describe, it, expect } from "vitest";
import { scanSecrets } from "../src/security/static/secrets.js";
import { scanUnicode } from "../src/security/static/unicode.js";

const scan = (text: string) => scanSecrets([{ label: "tool meta", text, location: "x" }]);

// NOTE: every credential below is assembled from fragments at runtime so that no scannable
// secret literal exists in this source file (otherwise GitHub push-protection / Merit itself
// would flag the test file). The runtime values are exactly the formats we want to detect.
describe("MCP01 secrets — catches real structured credentials", () => {
  const realKeys: Array<[string, string]> = [
    ["AWS access key", "AKIA" + "IOSFODNN7EXAMPLE"],
    ["GitHub token", "ghp_" + "a".repeat(36)],
    ["GitHub fine-grained PAT", "github_pat_" + "A".repeat(70)],
    ["OpenAI/Anthropic key", "sk-" + "live-9f8a7b6c5d4e3f2a1b0c"],
    ["Google API key", "AIza" + "a".repeat(35)],
    ["Slack token", "xox" + "b-123456789012-abcdefghijklmno"],
    ["Slack webhook", "https://hooks.slack.com/services/" + "A".repeat(45)],
    ["Stripe sk_live", "sk_" + "live_" + "a".repeat(24)],
    ["Stripe rk_live", "rk_" + "live_" + "a".repeat(24)],
    ["npm token", "npm_" + "a".repeat(36)],
    ["Azure AccountKey", "AccountKey=" + "a".repeat(86) + "=="],
    ["JWT", ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjMifQ", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"].join(".")],
  ];
  for (const [name, key] of realKeys) {
    it(`flags ${name}`, () => {
      expect(scan(`credential: ${key}`).length).toBeGreaterThanOrEqual(1);
    });
  }
  it("flags a PEM private key as critical", () => {
    const pem = ["-----BEGIN RSA PRIVATE", "KEY-----"].join(" ") + "\nMIIabc\n-----END RSA PRIVATE KEY-----";
    const f = scan(pem);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("critical");
  });
  it("flags a GCP service-account marker", () => {
    expect(scan('{ "type": "service' + '_account", "project_id": "x" }')).toHaveLength(1);
  });
});

describe("MCP01 secrets — does NOT cry wolf (anti-false-positive)", () => {
  const cleanCases: Array<[string, string]> = [
    ["plain prose", "This tool adds two numbers and returns the sum."],
    ["snake_case identifiers", "monarch_login_with_token get_session_alerts check_authentication"],
    ["a UUID", "id 550e8400-e29b-41d4-a716-446655440000"],
    ["a sha256 hash", "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["a base64 PNG", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="],
    ["a placeholder", "set OPENAI_API_KEY=your-api-key-here before running"],
  ];
  for (const [name, text] of cleanCases) {
    it(`ignores ${name}`, () => {
      expect(scan(text)).toHaveLength(0);
    });
  }
});

describe("MCP03a unicode poisoning", () => {
  it("detects zero-width space + bidi override", () => {
    const f = scanUnicode([{ label: "d", text: "hello​world‮", location: "x" }]);
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.confidence === "high")).toBe(true);
  });
  it("clean text produces no findings", () => {
    expect(scanUnicode([{ label: "d", text: "a normal tool description", location: "x" }])).toHaveLength(0);
  });
});
