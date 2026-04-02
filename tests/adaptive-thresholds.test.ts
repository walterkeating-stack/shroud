/**
 * Tests for the adaptive threshold engine.
 *
 * Verifies that thresholds are correctly adjusted based on profiler
 * baselines, hard caps are enforced, and immature baselines get
 * global defaults.
 */

import { describe, it, expect } from "vitest";
import { computeAdaptiveThresholds, isSignatureSuppressed } from "../src/adaptive-thresholds.js";
import type { AgentBaseline, RunningStats } from "../src/profiler-types.js";
import type { ShroudConfig } from "../src/types.js";
import { resolveConfig } from "../src/config.js";

function makeRunningStats(mean: number, m2: number, n: number): RunningStats {
  return { mean, m2, n, min: mean - 1, max: mean + 1 };
}

function makeBaseline(overrides: Partial<AgentBaseline> = {}): AgentBaseline {
  return {
    agentBuildId: "test1234abcd5678",
    sessionCount: 50,
    maturity: "mature",
    features: {},
    toolProfile: [],
    categoryProfile: [],
    lastUpdated: Date.now(),
    ...overrides,
  };
}

function getConfig(): ShroudConfig {
  return resolveConfig({
    secretKey: "test-key-adaptive-thresholds-1234",
    driftThreshold: 0.15,
    coherenceZScore: 3.0,
    transformerThreshold: 0.85,
  });
}

describe("computeAdaptiveThresholds", () => {
  it("returns global defaults when baseline is null", () => {
    const config = getConfig();
    const result = computeAdaptiveThresholds(null, config);
    expect(result.driftThreshold).toBe(config.driftThreshold);
    expect(result.coherenceZScore).toBe(config.coherenceZScore);
    expect(result.transformerThreshold).toBe(config.transformerThreshold);
    expect(result.suppressedSignatures).toEqual([]);
  });

  it("returns global defaults when baseline is learning", () => {
    const config = getConfig();
    const baseline = makeBaseline({ maturity: "learning", sessionCount: 3 });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.driftThreshold).toBe(config.driftThreshold);
    expect(result.coherenceZScore).toBe(config.coherenceZScore);
    expect(result.transformerThreshold).toBe(config.transformerThreshold);
    expect(result.suppressedSignatures).toEqual([]);
  });

  it("lowers drift threshold (less sensitive) for high lexical overlap stddev", () => {
    const config = getConfig();
    // High stddev: m2/(n-1) > 0.25^2 → m2 > 0.0625 * 49 ≈ 3.06
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        lexicalOverlapWithPrevious: makeRunningStats(0.5, 4.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    // Lower threshold = less sensitive (drift fires when similarity < threshold)
    expect(result.driftThreshold).toBeLessThan(config.driftThreshold);
    expect(result.driftThreshold).toBe(config.driftThreshold / 1.5);
  });

  it("does not adjust drift threshold for low lexical overlap stddev", () => {
    const config = getConfig();
    // Low stddev: m2/(n-1) < 0.25^2
    const baseline = makeBaseline({
      maturity: "reliable",
      features: {
        lexicalOverlapWithPrevious: makeRunningStats(0.7, 0.5, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.driftThreshold).toBe(config.driftThreshold);
  });

  it("widens coherence z-score for agents with many tools", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "reliable",
      toolProfile: ["tool1", "tool2", "tool3", "tool4", "tool5", "tool6", "tool7", "tool8"],
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.coherenceZScore).toBeGreaterThan(config.coherenceZScore);
    expect(result.coherenceZScore).toBe(config.coherenceZScore * 1.3);
  });

  it("does not widen coherence for agents with few tools", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "mature",
      toolProfile: ["tool1", "tool2"],
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.coherenceZScore).toBe(config.coherenceZScore);
  });

  it("raises transformer threshold for high entity density", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        entityDensityPer1k: makeRunningStats(6.0, 10.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.transformerThreshold).toBeGreaterThan(config.transformerThreshold);
    // 0.85 * 1.2 = 1.02, but capped at 0.95
    expect(result.transformerThreshold).toBe(0.95);
  });

  it("raises transformer threshold (below cap) for high entity density", () => {
    const config = resolveConfig({
      secretKey: "test-key-adaptive-thresholds-1234",
      transformerThreshold: 0.7,
    });
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        entityDensityPer1k: makeRunningStats(6.0, 10.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    // 0.7 * 1.2 = 0.84, below cap of 0.95
    expect(result.transformerThreshold).toBeCloseTo(0.84);
  });

  it("enforces hard floor on drift threshold (min 0.05)", () => {
    const config = resolveConfig({
      secretKey: "test-key-adaptive-thresholds-1234",
      driftThreshold: 0.06,
    });
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        lexicalOverlapWithPrevious: makeRunningStats(0.5, 4.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    // 0.06 / 1.5 = 0.04, floored to 0.05
    expect(result.driftThreshold).toBe(0.05);
  });

  it("enforces hard cap on coherence z-score (min 1.5)", () => {
    const config = resolveConfig({
      secretKey: "test-key-adaptive-thresholds-1234",
      coherenceZScore: 1.0,
    });
    const baseline = makeBaseline({
      maturity: "mature",
      toolProfile: Array.from({ length: 10 }, (_, i) => `tool${i}`),
    });
    const result = computeAdaptiveThresholds(baseline, config);
    // 1.0 * 1.3 = 1.3, floored to 1.5
    expect(result.coherenceZScore).toBe(1.5);
  });

  it("enforces hard cap on transformer threshold (max 0.95)", () => {
    const config = resolveConfig({
      secretKey: "test-key-adaptive-thresholds-1234",
      transformerThreshold: 0.9,
    });
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        entityDensityPer1k: makeRunningStats(10.0, 10.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    // 0.9 * 1.2 = 1.08, capped to 0.95
    expect(result.transformerThreshold).toBe(0.95);
  });

  it("suppresses tool_outside_profile when baseline has tools", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "reliable",
      toolProfile: ["read_file", "write_file"],
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.suppressedSignatures).toContain("tool_outside_profile");
  });

  it("suppresses topic_discontinuity for mature agents with high new vocab rate", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        newVocabularyRate: makeRunningStats(0.4, 1.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.suppressedSignatures).toContain("topic_discontinuity");
  });

  it("suppresses entity_density_spike for mature agents with high entity density", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "mature",
      features: {
        entityDensityPer1k: makeRunningStats(6.0, 10.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.suppressedSignatures).toContain("entity_density_spike");
  });

  it("does not suppress topic_discontinuity for reliable (non-mature) baselines", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "reliable",
      features: {
        newVocabularyRate: makeRunningStats(0.4, 1.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.suppressedSignatures).not.toContain("topic_discontinuity");
  });

  it("applies all adjustments simultaneously", () => {
    const config = getConfig();
    const baseline = makeBaseline({
      maturity: "mature",
      toolProfile: Array.from({ length: 10 }, (_, i) => `tool${i}`),
      features: {
        lexicalOverlapWithPrevious: makeRunningStats(0.5, 4.0, 50),
        entityDensityPer1k: makeRunningStats(6.0, 10.0, 50),
        newVocabularyRate: makeRunningStats(0.4, 1.0, 50),
      },
    });
    const result = computeAdaptiveThresholds(baseline, config);
    expect(result.driftThreshold).toBe(config.driftThreshold / 1.5);
    expect(result.coherenceZScore).toBe(config.coherenceZScore * 1.3);
    // 0.85 * 1.2 = 1.02, capped at 0.95
    expect(result.transformerThreshold).toBe(0.95);
    expect(result.suppressedSignatures).toContain("tool_outside_profile");
    expect(result.suppressedSignatures).toContain("topic_discontinuity");
    expect(result.suppressedSignatures).toContain("entity_density_spike");
  });
});

describe("isSignatureSuppressed", () => {
  it("returns true for suppressed signatures", () => {
    const thresholds = computeAdaptiveThresholds(
      makeBaseline({ maturity: "mature", toolProfile: ["a"] }),
      getConfig(),
    );
    expect(isSignatureSuppressed("tool_outside_profile", thresholds)).toBe(true);
  });

  it("returns false for non-suppressed signatures", () => {
    const thresholds = computeAdaptiveThresholds(null, getConfig());
    expect(isSignatureSuppressed("tool_outside_profile", thresholds)).toBe(false);
    expect(isSignatureSuppressed("some_random_sig", thresholds)).toBe(false);
  });
});
