import { describe, expect, it } from "vitest";
import { createFeatureCounterRegistry } from "../src/feature-counters.js";
import { resolveConfig } from "../src/config.js";

const DEFAULT_CONFIG = resolveConfig({});

describe("feature counter registry", () => {
  it("tracks global counters and agent-specific state", () => {
    const registry = createFeatureCounterRegistry(DEFAULT_CONFIG);

    registry.record("semantic_drift", {
      agentBuildId: "agent-1",
      agentLabel: "Research Agent",
      outcome: "suppressed",
      explanation: "Drift candidate suppressed during warmup.",
      suppressionReason: "behavioral warmup",
    });
    registry.record("semantic_drift", {
      agentBuildId: "agent-1",
      agentLabel: "Research Agent",
      outcome: "flagged",
      explanation: "Drift exceeded threshold.",
      thresholds: { similarity: 0.11, threshold: 0.15 },
    });

    const global = registry.getAll().find(f => f.id === "semantic_drift");
    expect(global).toBeTruthy();
    expect(global!.counters.evaluated).toBe(2);
    expect(global!.counters.suppressed).toBe(1);
    expect(global!.counters.flagged).toBe(1);
    expect(global!.lastSuppressionReason).toBeNull();
    expect(global!.thresholds).toEqual({ similarity: 0.11, threshold: 0.15 });

    const agent = registry.getForAgent("agent-1", "Research Agent").find(f => f.id === "semantic_drift");
    expect(agent).toBeTruthy();
    expect(agent!.counters.evaluated).toBe(2);
    expect(agent!.counters.suppressed).toBe(1);
    expect(agent!.counters.flagged).toBe(1);
  });

  it("summarizes enabled features and action counts", () => {
    const registry = createFeatureCounterRegistry(DEFAULT_CONFIG);
    registry.record("contract_enforcement", { outcome: "observed", explanation: "No violation." });
    registry.record("shadow_execution", { outcome: "blocked", explanation: "Shadow revealed exfil." });

    const summary = registry.getSummary();
    expect(summary.total).toBeGreaterThan(5);
    expect(summary.enabled).toBeGreaterThan(1);
    expect(summary.evaluated).toBe(2);
    expect(summary.blocked).toBe(1);
  });
});
