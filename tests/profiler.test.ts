/**
 * Tests for the behavioural profiling system (Track 3).
 *
 * Covers: feature extraction, Welford's algorithm, Z-score computation,
 * anomaly detection, baseline store, and session lifecycle.
 */

import { describe, test, expect, beforeEach, afterEach, afterAll } from "vitest";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

import {
  emptyStats,
  updateStats,
  stddev,
  zScore,
  detectAnomalies,
  updateBaseline,
  getTrackedFeatureNames,
} from "../src/profiler-analysis.js";
import { BaselineStore, computeAgentBuildId } from "../src/profiler-store.js";
import { BehaviouralProfiler } from "../src/profiler.js";
import { AnomalyType } from "../src/profiler-types.js";
import type { FeatureVector, RunningStats } from "../src/profiler-types.js";

// ===================================================================
// Welford's Algorithm
// ===================================================================

describe("Welford's Algorithm — Running Statistics", () => {
  test("empty stats", () => {
    const s = emptyStats();
    expect(s.mean).toBe(0);
    expect(s.n).toBe(0);
    expect(s.m2).toBe(0);
  });

  test("single observation", () => {
    let s = emptyStats();
    s = updateStats(s, 5);
    expect(s.mean).toBe(5);
    expect(s.n).toBe(1);
    expect(s.min).toBe(5);
    expect(s.max).toBe(5);
    expect(stddev(s)).toBe(0); // n < 2
  });

  test("known sequence: [2, 4, 4, 4, 5, 5, 7, 9]", () => {
    let s = emptyStats();
    for (const x of [2, 4, 4, 4, 5, 5, 7, 9]) {
      s = updateStats(s, x);
    }
    expect(s.mean).toBe(5);
    expect(s.n).toBe(8);
    expect(s.min).toBe(2);
    expect(s.max).toBe(9);
    // Population stddev of [2,4,4,4,5,5,7,9] = 2
    expect(stddev(s)).toBeCloseTo(2, 5);
  });

  test("constant values → stddev = 0", () => {
    let s = emptyStats();
    for (const x of [3, 3, 3, 3, 3]) {
      s = updateStats(s, x);
    }
    expect(s.mean).toBe(3);
    expect(stddev(s)).toBe(0);
  });

  test("large N stability", () => {
    let s = emptyStats();
    for (let i = 0; i < 1000; i++) {
      s = updateStats(s, 100 + (i % 10));
    }
    expect(s.n).toBe(1000);
    expect(s.mean).toBeCloseTo(104.5, 1);
    expect(stddev(s)).toBeGreaterThan(0);
  });
});

// ===================================================================
// Z-Score
// ===================================================================

describe("Z-Score Computation", () => {
  test("zero stddev, value equals mean → 0", () => {
    expect(zScore(5, 5, 0)).toBe(0);
  });

  test("zero stddev, value differs → Infinity", () => {
    expect(zScore(10, 5, 0)).toBe(Infinity);
  });

  test("known z-score", () => {
    expect(zScore(15, 10, 2)).toBe(2.5);
  });

  test("negative z-score", () => {
    expect(zScore(5, 10, 2)).toBe(-2.5);
  });
});

// ===================================================================
// Anomaly Detection
// ===================================================================

describe("Anomaly Detection", () => {
  function makeBaseline(): Record<string, RunningStats> {
    const baseline: Record<string, RunningStats> = {};
    // Simulate a baseline with 20 observations of entity density around 5.0±1.0
    let s = emptyStats();
    for (let i = 0; i < 20; i++) {
      s = updateStats(s, 4 + Math.random() * 2); // 4-6 range
    }
    baseline["entityDensityPer1k"] = s;

    // Lexical overlap baseline around 0.5±0.1
    let lo = emptyStats();
    for (let i = 0; i < 20; i++) {
      lo = updateStats(lo, 0.4 + Math.random() * 0.2);
    }
    baseline["lexicalOverlapWithPrevious"] = lo;

    return baseline;
  }

  function makeFeatureVector(overrides: Partial<FeatureVector> = {}): FeatureVector {
    return {
      entityCategoryCounts: {},
      entityDensityPer1k: 5,
      entityCategoryEntropy: 1.0,
      toolCallCount: 1,
      toolNames: ["read"],
      directiveVerbCount: 2,
      questionCount: 1,
      commandToQuestionRatio: 2,
      responseLength: 500,
      entityEchoRate: 0.1,
      lexicalOverlapWithPrevious: 0.5,
      newVocabularyRate: 0.3,
      turnIndex: 0,
      timestamp: Date.now(),
      tokenEstimate: 200,
      detectedScript: "latin",
      nonLatinRatio: 0,
      imagePayloadCount: 0,
      imagePayloadBytes: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      cacheHitRatio: 0,
      ...overrides,
    };
  }

  test("normal values → no anomalies", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector();
    const alerts = detectAnomalies(fv, baseline, 3, new Set(["read"]), new Set(["email"]));
    // Should have no density alerts since 5 is within normal range
    const densityAlerts = alerts.filter((a) => a.feature === "entityDensityPer1k");
    expect(densityAlerts).toHaveLength(0);
  });

  test("extreme entity density → anomaly", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector({ entityDensityPer1k: 50 }); // way above baseline ~5
    const alerts = detectAnomalies(fv, baseline, 3, new Set(["read"]), new Set(["email"]));
    const densityAlerts = alerts.filter((a) => a.type === AnomalyType.ENTITY_DENSITY_SPIKE);
    expect(densityAlerts.length).toBeGreaterThan(0);
  });

  test("unknown tool → TOOL_OUTSIDE_PROFILE", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector({ toolNames: ["read", "send_email"] });
    const alerts = detectAnomalies(fv, baseline, 3, new Set(["read"]), new Set(["email"]));
    const toolAlerts = alerts.filter((a) => a.type === AnomalyType.TOOL_OUTSIDE_PROFILE);
    expect(toolAlerts).toHaveLength(1);
    expect(toolAlerts[0].description).toContain("send_email");
  });

  test("credential emergence → critical alert", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector({
      entityCategoryCounts: { api_key: 3 },
    });
    const alerts = detectAnomalies(fv, baseline, 3, new Set(["read"]), new Set(["email"]));
    const credAlerts = alerts.filter((a) => a.type === AnomalyType.CREDENTIAL_EMERGENCE);
    expect(credAlerts).toHaveLength(1);
    expect(credAlerts[0].severity).toBe("critical");
  });

  test("known credential category → no credential alert", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector({
      entityCategoryCounts: { api_key: 3 },
    });
    // api_key is in known categories
    const alerts = detectAnomalies(fv, baseline, 3, new Set(["read"]), new Set(["api_key"]));
    const credAlerts = alerts.filter((a) => a.type === AnomalyType.CREDENTIAL_EMERGENCE);
    expect(credAlerts).toHaveLength(0);
  });

  test("empty known tools → no TOOL_OUTSIDE_PROFILE", () => {
    const baseline = makeBaseline();
    const fv = makeFeatureVector({ toolNames: ["anything"] });
    // Empty known tools means we're in early baseline — don't flag
    const alerts = detectAnomalies(fv, baseline, 3, new Set(), new Set());
    const toolAlerts = alerts.filter((a) => a.type === AnomalyType.TOOL_OUTSIDE_PROFILE);
    expect(toolAlerts).toHaveLength(0);
  });
});

// ===================================================================
// Baseline Store
// ===================================================================

describe("BaselineStore — File Persistence", () => {
  let tempDir: string;
  let store: BaselineStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "shroud-profile-test-"));
    store = new BaselineStore(tempDir);
  });

  afterEach(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  test("load returns null for nonexistent build", () => {
    expect(store.load("nonexistent")).toBeNull();
  });

  test("save and load roundtrip", () => {
    const baseline = {
      agentBuildId: "abc123",
      sessionCount: 5,
      maturity: "reliable" as const,
      features: {
        entityDensityPer1k: { mean: 5, m2: 10, n: 20, min: 1, max: 10 },
      },
      toolProfile: ["read", "write"],
      categoryProfile: ["email", "ip_address"],
      lastUpdated: Date.now(),
    };
    store.save("abc123", baseline);
    const loaded = store.load("abc123");
    expect(loaded).not.toBeNull();
    expect(loaded!.agentBuildId).toBe("abc123");
    expect(loaded!.sessionCount).toBe(5);
    expect(loaded!.features.entityDensityPer1k.mean).toBe(5);
  });

  test("exists returns true after save", () => {
    store.save("test123", {
      agentBuildId: "test123",
      sessionCount: 1,
      maturity: "learning",
      features: {},
      toolProfile: [],
      categoryProfile: [],
      lastUpdated: Date.now(),
    });
    expect(store.exists("test123")).toBe(true);
    expect(store.exists("other")).toBe(false);
  });

  test("maturity transitions", () => {
    // Simulate multiple session updates
    const buildId = "maturity_test";
    for (let i = 0; i < 6; i++) {
      store.updateFromSession(buildId, {
        sessionId: `sess_${i}`,
        agentBuildId: buildId,
        startedAt: Date.now(),
        turns: [{
          entityCategoryCounts: { email: 2 },
          entityDensityPer1k: 5,
          entityCategoryEntropy: 1,
          toolCallCount: 1,
          toolNames: ["read"],
          directiveVerbCount: 2,
          questionCount: 1,
          commandToQuestionRatio: 2,
          responseLength: 500,
          entityEchoRate: 0.1,
          lexicalOverlapWithPrevious: 0.5,
          newVocabularyRate: 0.3,
          turnIndex: 0,
          timestamp: Date.now(),
          tokenEstimate: 200,
          detectedScript: "latin",
          nonLatinRatio: 0,
          imagePayloadCount: 0,
          imagePayloadBytes: 0,
          inputTokens: 200,
          outputTokens: 100,
          cacheReadTokens: 140,
          cacheWriteTokens: 30,
          cacheHitRatio: 0.7,
        }],
        aggregates: {
          dominantCategories: ["email"],
          toolSequenceFingerprint: "abc",
          averageEntityDensity: 5,
          averageDirectiveVerbCount: 2,
          averageResponseLength: 500,
          averageLexicalOverlap: 0.5,
          turnCount: 1,
        },
      });
    }
    const loaded = store.load(buildId);
    expect(loaded!.sessionCount).toBe(6);
    expect(loaded!.maturity).toBe("reliable"); // 5+ sessions
  });

  // Cleanup
  afterAll(() => {
    try { rmSync(tempDir, { recursive: true }); } catch {}
  });
});

// ===================================================================
// Agent Build ID
// ===================================================================

describe("Agent Build ID", () => {
  test("deterministic for same inputs", () => {
    const id1 = computeAgentBuildId("System prompt", ["pluginA", "pluginB"], "claude-3");
    const id2 = computeAgentBuildId("System prompt", ["pluginA", "pluginB"], "claude-3");
    expect(id1).toBe(id2);
  });

  test("changes when system prompt changes", () => {
    const id1 = computeAgentBuildId("Prompt v1", ["pluginA"], "claude-3");
    const id2 = computeAgentBuildId("Prompt v2", ["pluginA"], "claude-3");
    expect(id1).not.toBe(id2);
  });

  test("changes when model changes", () => {
    const id1 = computeAgentBuildId("Prompt", ["pluginA"], "claude-3");
    const id2 = computeAgentBuildId("Prompt", ["pluginA"], "gpt-4");
    expect(id1).not.toBe(id2);
  });

  test("plugin order doesn't matter (sorted)", () => {
    const id1 = computeAgentBuildId("P", ["b", "a"], "m");
    const id2 = computeAgentBuildId("P", ["a", "b"], "m");
    expect(id1).toBe(id2);
  });

  test("returns 16-char hex string", () => {
    const id = computeAgentBuildId("x", [], "y");
    expect(id).toMatch(/^[a-f0-9]{16}$/);
  });
});

// ===================================================================
// BehaviouralProfiler — Feature Extraction
// ===================================================================

describe("BehaviouralProfiler — Feature Extraction", () => {
  let profiler: BehaviouralProfiler;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "shroud-profiler-test-"));
    profiler = new BehaviouralProfiler(
      { mode: "learning", sigma: 3, minBaseline: 5, profileDir: tempDir },
      new BaselineStore(tempDir),
    );
  });

  afterEach(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
  });

  test("extract request features from text", () => {
    profiler.extractRequestFeatures(
      "Please create a new user account and run the deployment script.",
      { email: 2, person_name: 1 },
      [{ name: "exec", arguments: {} }],
    );

    const fv = profiler.extractResponseFeatures("Done. Account created.", []);
    expect(fv).not.toBeNull();
    expect(fv!.entityDensityPer1k).toBeGreaterThan(0);
    expect(fv!.directiveVerbCount).toBeGreaterThan(0); // "create", "run"
    expect(fv!.toolCallCount).toBe(1);
    expect(fv!.toolNames).toEqual(["exec"]);
    expect(fv!.responseLength).toBe("Done. Account created.".length);
  });

  test("entity echo rate computed correctly", () => {
    profiler.extractRequestFeatures(
      "Check user john@example.com at IP 10.0.0.1",
      { email: 1, ip_address: 1 },
    );

    // Response contains one of the two entities
    const fv = profiler.extractResponseFeatures(
      "User john@example.com is active.",
      ["john@example.com", "10.0.0.1"],
    );
    expect(fv!.entityEchoRate).toBe(0.5); // 1 of 2 echoed
  });

  test("lexical overlap decreases with topic shift", () => {
    // Turn 1: network topic
    profiler.extractRequestFeatures(
      "Configure the router interface with OSPF and BGP routing protocol",
      {},
    );
    profiler.extractResponseFeatures("Configuration applied.", []);

    // Turn 2: same topic
    profiler.extractRequestFeatures(
      "Show the router interface status and BGP routing table",
      {},
    );
    const fv2 = profiler.extractResponseFeatures("Status shown.", []);
    const overlap2 = fv2!.lexicalOverlapWithPrevious;

    // Turn 3: completely different topic
    profiler.extractRequestFeatures(
      "Write a Python function to calculate fibonacci numbers recursively",
      {},
    );
    const fv3 = profiler.extractResponseFeatures("Function written.", []);
    const overlap3 = fv3!.lexicalOverlapWithPrevious;

    // Topic shift should reduce lexical overlap
    expect(overlap3).toBeLessThan(overlap2);
  });

  test("question count detection", () => {
    profiler.extractRequestFeatures(
      "What is the status? Is it running? Please check.",
      {},
    );
    const fv = profiler.extractResponseFeatures("Yes.", []);
    expect(fv!.questionCount).toBe(2);
  });

  test("session profile aggregates", () => {
    profiler.setAgentBuildId("test-build");

    for (let i = 0; i < 3; i++) {
      profiler.extractRequestFeatures(`Turn ${i} with email and IP data.`, { email: 1 });
      profiler.extractResponseFeatures(`Response ${i}`, []);
    }

    const profile = profiler.getSessionProfile();
    expect(profile.turns).toHaveLength(3);
    expect(profile.agentBuildId).toBe("test-build");
    expect(profile.aggregates.turnCount).toBe(3);
    expect(profile.aggregates.dominantCategories).toContain("email");
  });

  test("learning mode returns no alerts", () => {
    profiler.setAgentBuildId("test");
    profiler.extractRequestFeatures("Test input.", {});
    const fv = profiler.extractResponseFeatures("Test output.", []);
    const alerts = profiler.analyzeTurn(fv!);
    expect(alerts).toHaveLength(0); // learning mode
  });

  test("finalize session persists to store", () => {
    const store = new BaselineStore(tempDir);
    const p = new BehaviouralProfiler(
      { mode: "learning", sigma: 3, minBaseline: 5, profileDir: tempDir },
      store,
    );
    p.setAgentBuildId("persist-test");
    p.extractRequestFeatures("Input.", { email: 1 });
    p.extractResponseFeatures("Output.", []);
    p.finalizeSession();

    const baseline = store.load("persist-test");
    expect(baseline).not.toBeNull();
    expect(baseline!.sessionCount).toBe(1);
    expect(baseline!.maturity).toBe("learning");
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true }); } catch {}
  });
});

// ===================================================================
// Config — Profiling Fields
// ===================================================================

describe("Config — Profiling Fields", () => {
  // Dynamic import to get fresh config each time
  let resolveConfig: any;
  beforeEach(async () => {
    const mod = await import("../src/config.js");
    resolveConfig = mod.resolveConfig;
  });

  test("profilingEnabled defaults to false", () => {
    const config = resolveConfig({});
    expect(config.profilingEnabled).toBe(false);
  });

  test("profilingMode defaults to learning", () => {
    const config = resolveConfig({});
    expect(config.profilingMode).toBe("learning");
  });

  test("profilingSigma defaults to 3.0", () => {
    const config = resolveConfig({});
    expect(config.profilingSigma).toBe(3.0);
  });

  test("canarySystemInjection defaults to false", () => {
    const config = resolveConfig({});
    expect(config.canarySystemInjection).toBe(false);
  });

  test("canaryBehavioural defaults to false", () => {
    const config = resolveConfig({});
    expect(config.canaryBehavioural).toBe(false);
  });

  test("canaryNearMatchDistance defaults to 2", () => {
    const config = resolveConfig({});
    expect(config.canaryNearMatchDistance).toBe(2);
  });
});

// ===================================================================
// Tracked Features
// ===================================================================

describe("Tracked Feature Names", () => {
  test("returns at least 8 features", () => {
    const names = getTrackedFeatureNames();
    expect(names.length).toBeGreaterThanOrEqual(8);
  });

  test("includes key features", () => {
    const names = getTrackedFeatureNames();
    expect(names).toContain("entityDensityPer1k");
    expect(names).toContain("lexicalOverlapWithPrevious");
    expect(names).toContain("toolCallCount");
  });
});
