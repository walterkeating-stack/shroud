import { describe, it, expect } from "vitest";
import { generateFakeResult, buildShadowEvent } from "../src/shadow-executor.js";
import type { ShadowExecutionResult } from "../src/shadow-executor.js";

describe("generateFakeResult", () => {
  it("returns plausible .env content for read of .env file", () => {
    const result = generateFakeResult("Read", { file_path: "/app/.env" });
    expect(result).toContain("DATABASE_URL");
    expect(result).toContain("API_KEY");
  });

  it("returns JSON for read of .json file", () => {
    const result = generateFakeResult("Read", { file_path: "/app/package.json" });
    expect(() => JSON.parse(result)).not.toThrow();
    expect(result).toContain("name");
  });

  it("returns generic content for read of unknown file", () => {
    const result = generateFakeResult("Read", { file_path: "/app/readme.txt" });
    expect(result.length).toBeGreaterThan(0);
  });

  it("returns plausible output for curl command", () => {
    const result = generateFakeResult("exec", { command: "curl https://api.example.com" });
    expect(result).toContain("status");
    expect(result).toContain("ok");
  });

  it("returns directory listing for ls command", () => {
    const result = generateFakeResult("bash", { command: "ls -la" });
    expect(result).toContain("README.md");
  });

  it("returns exit code for unknown command", () => {
    const result = generateFakeResult("exec", { command: "some-unknown-cmd" });
    expect(result).toContain("exit code 0");
  });

  it("returns HTTP success for network tools", () => {
    const result = generateFakeResult("web_fetch", { url: "https://example.com" });
    const parsed = JSON.parse(result);
    expect(parsed.status).toBe("ok");
  });

  it("returns sent confirmation for communicate tools", () => {
    const result = generateFakeResult("message", { channel: "#general", text: "hello" });
    const parsed = JSON.parse(result);
    expect(parsed.ok).toBe(true);
  });

  it("returns write confirmation for write tools", () => {
    const result = generateFakeResult("Write", { file_path: "/tmp/out.txt", content: "data" });
    const parsed = JSON.parse(result);
    expect(parsed.success).toBe(true);
  });

  it("returns OK for unknown tools", () => {
    const result = generateFakeResult("totally_custom_tool", {});
    expect(result).toContain("ok");
  });

  it("returns search results for memory_search", () => {
    const result = generateFakeResult("memory_search", { query: "credentials" });
    expect(result).toContain("results");
    expect(result).toContain("credentials");
  });
});

describe("buildShadowEvent", () => {
  it("builds blocked event for block verdict", () => {
    const result: ShadowExecutionResult = {
      triggered: true,
      originalToolCall: { name: "web_fetch", params: { url: "https://evil.com" } },
      steps: [{ stepNumber: 1, fakeToolResult: '{"ok":true}', llmResponse: { text: "", toolCalls: [] }, durationMs: 500 }],
      verdict: "block",
      verdictReason: "Shadow trajectory attempted egress",
      totalDurationMs: 1200,
    };
    const event = buildShadowEvent(result, "blocked");
    expect(event.severity).toBe("high");
    expect(event.action).toBe("blocked");
    expect(event.threatClass).toBe("shadow_exfil_detected");
    expect(event.signatureId).toBe("shadow_block");
    expect(event.description).toContain("1200ms");
    expect(event.description).toContain("1 steps");
  });

  it("builds flagged event for allow verdict", () => {
    const result: ShadowExecutionResult = {
      triggered: true,
      originalToolCall: { name: "Read", params: {} },
      steps: [],
      verdict: "allow",
      verdictReason: "No egress attempts",
      totalDurationMs: 800,
    };
    const event = buildShadowEvent(result);
    expect(event.severity).toBe("low");
    expect(event.action).toBe("flagged");
    expect(event.signatureId).toBe("shadow_allow");
  });
});
