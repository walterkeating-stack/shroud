/**
 * Tests for the firewall rule suggestion engine.
 *
 * Verifies that suggestions are correctly generated from event data,
 * and that accept/dismiss work correctly.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { RuleSuggestionEngine } from "../src/rule-suggestions.js";
import type { SecurityEvent } from "../src/security-event.js";
import type { AgentBaseline } from "../src/profiler-types.js";
import { resolveConfig } from "../src/config.js";
import { PolicyEngine } from "../src/policy.js";
import { BaselineStore } from "../src/profiler-store.js";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: "semantic_drift" as any,
    signatureId: "drift_threshold",
    severity: "medium",
    matchedText: "test event",
    matchStart: 0,
    matchEnd: 10,
    textLength: 100,
    action: "flagged",
    description: "Test event",
    agentBuildId: "agent001",
    agentLabel: "Test Agent",
    agentSessionId: "session001",
    ...overrides,
  };
}

function getConfig() {
  return resolveConfig({
    secretKey: "test-key-rule-suggestions-1234",
    driftThreshold: 0.15,
    coherenceZScore: 3.0,
    transformerThreshold: 0.85,
  });
}

describe("RuleSuggestionEngine", () => {
  let engine: RuleSuggestionEngine;

  beforeEach(() => {
    engine = new RuleSuggestionEngine();
  });

  it("returns no suggestions for empty events", () => {
    const suggestions = engine.generateSuggestions([], null, getConfig());
    expect(suggestions).toHaveLength(0);
  });

  it("suggests suppressing signature for mature agent with high event count", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-rule-sug-"));
    const store = new BaselineStore(tmpDir);
    const baseline: AgentBaseline = {
      agentBuildId: "agent001",
      sessionCount: 50,
      maturity: "mature",
      features: {},
      toolProfile: [],
      categoryProfile: [],
      lastUpdated: Date.now(),
    };
    store.save("agent001", baseline);

    const events: SecurityEvent[] = [];
    for (let i = 0; i < 10; i++) {
      events.push(makeEvent({ timestamp: Date.now() - i * 1000, signatureId: "drift_threshold" }));
    }

    const suggestions = engine.generateSuggestions(events, store, getConfig());
    const suppressSuggestion = suggestions.find(s => s.type === "suppress" && s.signatureId === "drift_threshold");
    expect(suppressSuggestion).toBeDefined();
    expect(suppressSuggestion!.agentBuildId).toBe("agent001");
    expect(suppressSuggestion!.confidence).toBeGreaterThan(0);
    expect(suppressSuggestion!.impact).toContain("events/day");
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("suggests widening thresholds when >50% events are drift/coherence", () => {
    const events: SecurityEvent[] = [];
    // 6 drift events + 2 injection events = 75% drift
    for (let i = 0; i < 6; i++) {
      events.push(makeEvent({ signatureId: "semantic_drift", timestamp: Date.now() - i * 1000 }));
    }
    for (let i = 0; i < 2; i++) {
      events.push(makeEvent({ signatureId: "io_jailbreak", timestamp: Date.now() - i * 1000 }));
    }

    const suggestions = engine.generateSuggestions(events, null, getConfig());
    const widenSuggestion = suggestions.find(s => s.type === "widen_threshold");
    expect(widenSuggestion).toBeDefined();
    expect(widenSuggestion!.reason).toContain("75%");
  });

  it("does not suggest widening when drift/coherence is under 50%", () => {
    const events: SecurityEvent[] = [];
    // 2 drift + 4 injection = 33% drift
    for (let i = 0; i < 2; i++) {
      events.push(makeEvent({ signatureId: "drift_threshold", timestamp: Date.now() - i * 1000 }));
    }
    for (let i = 0; i < 4; i++) {
      events.push(makeEvent({ signatureId: "io_jailbreak", timestamp: Date.now() - i * 1000 }));
    }

    const suggestions = engine.generateSuggestions(events, null, getConfig());
    const widenSuggestion = suggestions.find(s => s.type === "widen_threshold");
    expect(widenSuggestion).toBeUndefined();
  });

  it("suggests per-agent suppress for single-agent signatures", () => {
    const events: SecurityEvent[] = [];
    // 5 events from same agent, same signature
    for (let i = 0; i < 5; i++) {
      events.push(makeEvent({
        signatureId: "unusual_signature",
        agentBuildId: "agent002",
        agentLabel: "Only Agent",
        timestamp: Date.now() - i * 1000,
      }));
    }

    const suggestions = engine.generateSuggestions(events, null, getConfig());
    const singleSuggestion = suggestions.find(s =>
      s.signatureId === "unusual_signature" && s.agentBuildId === "agent002"
    );
    expect(singleSuggestion).toBeDefined();
    expect(singleSuggestion!.reason).toContain("only triggered by");
  });

  it("dismissed suggestions do not reappear", () => {
    const events: SecurityEvent[] = [];
    for (let i = 0; i < 5; i++) {
      events.push(makeEvent({
        signatureId: "test_sig",
        agentBuildId: "agent003",
        agentLabel: "DismissTest",
        timestamp: Date.now() - i * 1000,
      }));
    }

    const before = engine.generateSuggestions(events, null, getConfig());
    const suggestion = before.find(s => s.signatureId === "test_sig");
    expect(suggestion).toBeDefined();

    engine.dismissSuggestion(suggestion!.id);
    expect(engine.isDismissed(suggestion!.id)).toBe(true);

    const after = engine.generateSuggestions(events, null, getConfig());
    const dismissed = after.find(s => s.id === suggestion!.id);
    expect(dismissed).toBeUndefined();
  });

  it("accepts suppress suggestion and updates policy", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-rule-accept-"));
    const policyPath = join(tmpDir, "policy.json");
    const policyEngine = new PolicyEngine(policyPath);

    const suggestion = {
      id: "suppress:agent001:test_sig",
      agentBuildId: "agent001",
      agentLabel: "Test Agent",
      type: "suppress" as const,
      signatureId: "test_sig",
      reason: "test reason",
      confidence: 0.8,
      impact: "test impact",
    };

    const result = engine.acceptSuggestion(suggestion, policyEngine);
    expect(result).toBe(true);

    const policy = policyEngine.getPolicy("agent001");
    expect(policy.injectionDisabledSignatures).toContain("test_sig");
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("accepts widen_threshold suggestion and creates policy note", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-rule-widen-"));
    const policyPath = join(tmpDir, "policy.json");
    const policyEngine = new PolicyEngine(policyPath);

    const suggestion = {
      id: "widen:agent001:drift_coherence",
      agentBuildId: "agent001",
      agentLabel: "Test Agent",
      type: "widen_threshold" as const,
      reason: "test widen reason",
      confidence: 0.7,
      impact: "test impact",
    };

    engine.acceptSuggestion(suggestion, policyEngine);
    const policy = policyEngine.getPolicy("agent001");
    expect(policy.notes).toContain("Auto-widened");
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("sorts suggestions by confidence descending", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-rule-sort-"));
    const store = new BaselineStore(tmpDir);

    // Agent A: mature, many events → high confidence
    const baselineA: AgentBaseline = {
      agentBuildId: "agentA",
      sessionCount: 100,
      maturity: "mature",
      features: {},
      toolProfile: [],
      categoryProfile: [],
      lastUpdated: Date.now(),
    };
    store.save("agentA", baselineA);

    const events: SecurityEvent[] = [];
    for (let i = 0; i < 20; i++) {
      events.push(makeEvent({
        signatureId: "sig_a",
        agentBuildId: "agentA",
        agentLabel: "Agent A",
        timestamp: Date.now() - i * 1000,
      }));
    }
    // Agent B: fewer events
    for (let i = 0; i < 3; i++) {
      events.push(makeEvent({
        signatureId: "sig_b",
        agentBuildId: "agentB",
        agentLabel: "Agent B",
        timestamp: Date.now() - i * 1000,
      }));
    }

    const suggestions = engine.generateSuggestions(events, store, getConfig());
    if (suggestions.length >= 2) {
      for (let i = 1; i < suggestions.length; i++) {
        expect(suggestions[i - 1].confidence).toBeGreaterThanOrEqual(suggestions[i].confidence);
      }
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("prunes stale dismissed entries", () => {
    // Manually insert old dismissed entry
    (engine as any)._dismissed.set("old_id", { id: "old_id", timestamp: Date.now() - 8 * 24 * 60 * 60 * 1000 });
    (engine as any)._dismissed.set("new_id", { id: "new_id", timestamp: Date.now() });

    const pruned = engine.pruneStale();
    expect(pruned).toBe(1);
    expect(engine.isDismissed("old_id")).toBe(false);
    expect(engine.isDismissed("new_id")).toBe(true);
  });

  it("ignores events from unknown agents", () => {
    const events = [makeEvent({ agentBuildId: undefined, agentLabel: undefined })];
    const suggestions = engine.generateSuggestions(events, null, getConfig());
    // No suggestions since agent is unknown
    expect(suggestions.filter(s => s.agentBuildId === "unknown")).toHaveLength(0);
  });
});
