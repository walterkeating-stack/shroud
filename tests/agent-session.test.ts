/**
 * Tests for agent session tracking.
 */

import { describe, test, expect, beforeEach } from "vitest";
import { AgentSessionTracker, computeBuildId } from "../src/agent-session.js";

describe("AgentSessionTracker", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  test("registerAgent creates a session", () => {
    const session = tracker.registerAgent("You are a helpful research assistant.");
    expect(session.agentBuildId).toMatch(/^[a-f0-9]{16}$/);
    expect(session.sessionId).toMatch(/^[a-f0-9]{12}$/);
    expect(session.llmCallCount).toBe(0);
    expect(session.agentLabel).toContain("helpful research assistant");
  });

  test("same system prompt returns same session", () => {
    const s1 = tracker.registerAgent("You are a research assistant.");
    const s2 = tracker.registerAgent("You are a research assistant.");
    expect(s1.agentBuildId).toBe(s2.agentBuildId);
    expect(s1.sessionId).toBe(s2.sessionId);
  });

  test("different system prompt creates different session", () => {
    const s1 = tracker.registerAgent("You are a research assistant.");
    const s2 = tracker.registerAgent("You are a code reviewer.");
    expect(s1.agentBuildId).not.toBe(s2.agentBuildId);
  });

  test("recordLlmCall increments count", () => {
    tracker.registerAgent("Agent A");
    tracker.recordLlmCall();
    tracker.recordLlmCall();
    tracker.recordLlmCall();
    const session = tracker.getCurrentSession();
    expect(session!.llmCallCount).toBe(3);
  });

  test("recordSecurityEvent increments count", () => {
    tracker.registerAgent("Agent A");
    tracker.recordSecurityEvent(2);
    tracker.recordSecurityEvent(1);
    const session = tracker.getCurrentSession();
    expect(session!.securityEventCount).toBe(3);
  });

  test("getCurrentSession returns current agent", () => {
    tracker.registerAgent("Agent A");
    expect(tracker.getCurrentSession()!.agentLabel).toContain("Agent A");

    tracker.registerAgent("Agent B");
    expect(tracker.getCurrentSession()!.agentLabel).toContain("Agent B");
  });

  test("getAllSessions returns all tracked agents", () => {
    tracker.registerAgent("Agent A");
    tracker.registerAgent("Agent B");
    tracker.registerAgent("Agent C");
    expect(tracker.getAllSessions()).toHaveLength(3);
  });

  test("reset clears all sessions", () => {
    tracker.registerAgent("Agent A");
    tracker.reset();
    expect(tracker.getAllSessions()).toHaveLength(0);
    expect(tracker.getCurrentSession()).toBeNull();
  });

  test("extractLabel handles long prompts", () => {
    const longPrompt = "A".repeat(100) + "\nSecond line.";
    const session = tracker.registerAgent(longPrompt);
    expect(session.agentLabel.length).toBeLessThanOrEqual(60);
  });

  test("extractLabel handles comments and headers", () => {
    const session = tracker.registerAgent("# Title\n<!-- comment -->\nYou are a helpful assistant.");
    expect(session.agentLabel).toContain("helpful assistant");
  });
});

describe("computeBuildId", () => {
  test("deterministic", () => {
    const a = computeBuildId("prompt", ["p1"], "model");
    const b = computeBuildId("prompt", ["p1"], "model");
    expect(a).toBe(b);
  });

  test("plugin order invariant", () => {
    const a = computeBuildId("p", ["b", "a"], "m");
    const b = computeBuildId("p", ["a", "b"], "m");
    expect(a).toBe(b);
  });

  test("changes with prompt", () => {
    const a = computeBuildId("v1", [], "m");
    const b = computeBuildId("v2", [], "m");
    expect(a).not.toBe(b);
  });

  test("returns 16-char hex", () => {
    expect(computeBuildId("x", [], "y")).toMatch(/^[a-f0-9]{16}$/);
  });
});
