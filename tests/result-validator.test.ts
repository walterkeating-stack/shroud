/**
 * Result validator tests — intent-to-result matching.
 *
 * Tests the three heuristics:
 * 1. Category escalation: high-sensitivity PII in non-read tool results
 * 2. Exfil chain: PII-containing results followed by egress tools
 * 3. Bulk sensitive: large results with many PII categories
 */

import { describe, test, expect } from "vitest";
import { createTurnContext, validateToolResult, checkExfilChain } from "../src/detectors/result-validator.js";
import { extractIntentSignals, ToolCategory } from "../src/detectors/tool-intent.js";

// ─── Heuristic 1: Category escalation ───

describe("Category escalation detection", () => {
  test("exec result with API key when user asked to 'summarize' → flagged", () => {
    const intent = extractIntentSignals("Summarize the README file");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key", "email"]), 500);
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].signatureId).toBe("rv_category_escalation");
    expect(events[0].severity).toBe("high");
  });

  test("exec result with API key when user mentioned 'API keys' → NOT flagged", () => {
    const intent = extractIntentSignals("Show me the API keys in the config file");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key"]), 500);
    expect(events).toHaveLength(0);
  });

  test("read result with SSN → NOT flagged (read-only tools exempt)", () => {
    const intent = extractIntentSignals("What's in this file?");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "Read", category: ToolCategory.READ_ONLY, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["ssn", "person_name"]), 500);
    expect(events).toHaveLength(0);
  });

  test("network result with credentials when user didn't mention creds → flagged", () => {
    const intent = extractIntentSignals("Check the homepage");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "web_fetch", category: ToolCategory.NETWORK, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["network_credential", "jwt"]), 500);
    expect(events.length).toBeGreaterThan(0);
  });

  test("result with only non-sensitive PII (email, ip) → NOT flagged", () => {
    const intent = extractIntentSignals("Run the test suite");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["email", "ip_address"]), 500);
    expect(events).toHaveLength(0);
  });

  test("write result → NOT flagged (local workspace exempt)", () => {
    const intent = extractIntentSignals("Do something");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "Write", category: ToolCategory.WRITE_LOCAL, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key", "ssn"]), 500);
    expect(events).toHaveLength(0);
  });
});

// ─── Heuristic 2: Exfil chain ───

describe("Exfil chain detection", () => {
  test("read with PII → message call without communication intent → flagged", () => {
    const intent = extractIntentSignals("Summarize the report");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["email", "person_name"]),
      resultSize: 500,
    });

    const event = checkExfilChain(ctx, "message");
    expect(event).not.toBeNull();
    expect(event!.severity).toBe("high");
    expect(event!.signatureId).toBe("rv_exfil_chain");
  });

  test("read with PII → message call WITH communication intent → NOT flagged", () => {
    const intent = extractIntentSignals("Read the file and send the summary to Walter");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["email", "person_name"]),
      resultSize: 500,
    });

    const event = checkExfilChain(ctx, "message");
    expect(event).toBeNull();
  });

  test("read with PII → web_fetch without network intent → flagged", () => {
    const intent = extractIntentSignals("Summarize the document");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["api_key"]),
      resultSize: 200,
    });

    const event = checkExfilChain(ctx, "web_fetch");
    expect(event).not.toBeNull();
    expect(event!.severity).toBe("high");
  });

  test("no previous PII → message call → NOT flagged", () => {
    const intent = extractIntentSignals("Hello");
    const ctx = createTurnContext(intent);
    // No previous tool results

    const event = checkExfilChain(ctx, "message");
    expect(event).toBeNull();
  });

  test("read tool called → NOT flagged (read is not egress)", () => {
    const intent = extractIntentSignals("Summarize this");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "exec",
      category: ToolCategory.EXECUTE,
      resultCategories: new Set(["email"]),
      resultSize: 500,
    });

    const event = checkExfilChain(ctx, "Read");
    expect(event).toBeNull();
  });

  test("write tool called → NOT flagged (local write is not egress)", () => {
    const intent = extractIntentSignals("Summarize this");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["email"]),
      resultSize: 500,
    });

    const event = checkExfilChain(ctx, "Write");
    expect(event).toBeNull();
  });
});

// ─── Heuristic 3: Bulk sensitive data ───

describe("Bulk sensitive data detection", () => {
  test("large exec result with many PII categories → flagged", () => {
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["email", "person_name", "ssn", "ip_address"]), 15_000);
    expect(events.some(e => e.signatureId === "rv_bulk_sensitive")).toBe(true);
  });

  test("large read result → NOT flagged (read exempt)", () => {
    const intent = extractIntentSignals("Read the database dump");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "Read", category: ToolCategory.READ_ONLY, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["email", "person_name", "ssn", "ip_address"]), 50_000);
    expect(events.filter(e => e.signatureId === "rv_bulk_sensitive")).toHaveLength(0);
  });

  test("small exec result → NOT flagged", () => {
    const intent = extractIntentSignals("Run tests");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["email", "person_name", "ssn"]), 500);
    expect(events.filter(e => e.signatureId === "rv_bulk_sensitive")).toHaveLength(0);
  });
});

// ─── False positive prevention ───

describe("No false positives on legitimate workflows", () => {
  test("user asks to read .env → Read returns api_key → no flag", () => {
    const intent = extractIntentSignals("Read the .env file and check the API keys");
    const ctx = createTurnContext(intent);
    ctx.pendingToolCall = { toolName: "Read", category: ToolCategory.READ_ONLY, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key", "email"]), 300);
    expect(events).toHaveLength(0);
  });

  test("user asks to send summary → read then message → no exfil flag", () => {
    const intent = extractIntentSignals("Read the report and send a summary to the team");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["email", "person_name", "ip_address"]),
      resultSize: 2000,
    });

    expect(checkExfilChain(ctx, "message")).toBeNull();
  });

  test("user asks to fetch URL → web_fetch returns data → no exfil flag", () => {
    const intent = extractIntentSignals("Fetch the data from https://api.example.com");
    const ctx = createTurnContext(intent);
    ctx.toolResults.push({
      toolName: "Read",
      category: ToolCategory.READ_ONLY,
      resultCategories: new Set(["email"]),
      resultSize: 100,
    });

    expect(checkExfilChain(ctx, "web_fetch")).toBeNull();
  });
});

// ─── Heuristic 4: Baseline deviation ───

describe("Baseline deviation detection", () => {
  const matureBaseline = {
    agentBuildId: "test-agent-123",
    sessionCount: 10,
    maturity: "mature" as const,
    features: {},
    toolProfile: ["Read", "Write", "exec"],
    categoryProfile: ["email", "ip_address", "hostname", "person_name"],
    lastUpdated: Date.now(),
  };

  test("novel sensitive category not in baseline → flagged", () => {
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent, matureBaseline);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    // api_key is not in the baseline's categoryProfile
    const events = validateToolResult(ctx, new Set(["email", "api_key"]), 500);
    expect(events.some(e => e.signatureId === "rv_baseline_deviation")).toBe(true);
  });

  test("known categories from baseline → NOT flagged", () => {
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent, matureBaseline);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    // All categories are in the baseline
    const events = validateToolResult(ctx, new Set(["email", "ip_address"]), 500);
    expect(events.filter(e => e.signatureId === "rv_baseline_deviation")).toHaveLength(0);
  });

  test("novel non-sensitive category → NOT flagged", () => {
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent, matureBaseline);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    // vlan_id is novel but not in HIGH_SENSITIVITY
    const events = validateToolResult(ctx, new Set(["email", "vlan_id"]), 500);
    expect(events.filter(e => e.signatureId === "rv_baseline_deviation")).toHaveLength(0);
  });

  test("learning baseline → NOT flagged (not enough data)", () => {
    const learningBaseline = { ...matureBaseline, maturity: "learning" as const, sessionCount: 2 };
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent, learningBaseline);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key", "ssn"]), 500);
    expect(events.filter(e => e.signatureId === "rv_baseline_deviation")).toHaveLength(0);
  });

  test("no baseline → NOT flagged", () => {
    const intent = extractIntentSignals("Check the system");
    const ctx = createTurnContext(intent, null);
    ctx.pendingToolCall = { toolName: "exec", category: ToolCategory.EXECUTE, timestamp: Date.now() };

    const events = validateToolResult(ctx, new Set(["api_key"]), 500);
    expect(events.filter(e => e.signatureId === "rv_baseline_deviation")).toHaveLength(0);
  });
});
