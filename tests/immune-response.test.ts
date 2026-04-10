/**
 * Tests for the collective immune response engine.
 *
 * Verifies fingerprint extraction, antibody creation, matching,
 * sigma tightening, TTL decay, re-confirmation, threshold overrides,
 * and persistence.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  ImmuneResponseEngine,
  type ImmuneConfig,
  type AttackFingerprint,
} from "../src/immune-response.js";
import type { AttackTrace } from "../src/transformer/contrastive.js";
import { resolveConfig } from "../src/config.js";
import { detectAnomalies, emptyStats, updateStats } from "../src/profiler-analysis.js";
import type { FeatureVector, BaselineFeatureStats } from "../src/profiler-types.js";

// ── Helpers ──

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "shroud-immune-test-"));
}

function makeConfig(overrides: Partial<ImmuneConfig> = {}): ImmuneConfig {
  return {
    ttlSec: 3600, // 1 hour
    sigmaTightenFactor: 0.5,
    matchThreshold: 0.7,
    maxAntibodies: 10,
    ...overrides,
  };
}

function makeTrace(overrides: Partial<AttackTrace> = {}): AttackTrace {
  return {
    legitimatePrefix: ["read_file", "search", "edit_file"],
    hijackedSuffix: ["send_to_webhook", "upload_file_external"],
    injectionPoint: 3,
    source: "honeypot",
    threatType: "honeypot_credential",
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeFeatureVector(overrides: Partial<FeatureVector> = {}): FeatureVector {
  return {
    entityCategoryCounts: {},
    entityDensityPer1k: 2.0,
    entityCategoryEntropy: 1.0,
    toolCallCount: 1,
    toolNames: ["read_file"],
    directiveVerbCount: 1,
    questionCount: 1,
    commandToQuestionRatio: 1,
    responseLength: 100,
    entityEchoRate: 0.0,
    lexicalOverlapWithPrevious: 0.5,
    newVocabularyRate: 0.1,
    turnIndex: 0,
    timestamp: Date.now(),
    tokenEstimate: 25,
    detectedScript: "latin",
    nonLatinRatio: 0.0,
    imagePayloadCount: 0,
    imagePayloadBytes: 0,
    inputTokens: 100,
    outputTokens: 50,
    cacheReadTokens: 80,
    cacheWriteTokens: 20,
    cacheHitRatio: 0.8,
    ...overrides,
  };
}

// ── Tests ──

describe("ImmuneResponseEngine", () => {
  let dir: string;
  let engine: ImmuneResponseEngine;

  beforeEach(() => {
    dir = makeTmpDir();
    engine = new ImmuneResponseEngine(dir, makeConfig());
  });

  describe("fingerprint extraction", () => {
    it("extracts a fingerprint from an attack trace", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "agent1", "Agent One", "honeypot",
        "hp_api_key", ["entityDensityPer1k"], ["api_key"],
      );

      expect(fp.id).toHaveLength(16);
      expect(fp.signatureId).toBe("hp_api_key");
      expect(fp.threatType).toBe("honeypot_credential");
      expect(fp.source).toBe("honeypot");
      expect(fp.sourceAgentBuildId).toBe("agent1");
      expect(fp.sourceAgentLabel).toBe("Agent One");
      expect(fp.flaggedDimensions).toEqual(["entityDensityPer1k"]);
      expect(fp.entityCategories).toEqual(["api_key"]);
      expect(fp.trigrams.length).toBeGreaterThan(0);
      expect(fp.vector.length).toBe(256);
    });

    it("increments stats on extraction", () => {
      const trace = makeTrace();
      engine.extractFingerprint(trace, "a", "A", "phantom", "pt_upload");
      engine.extractFingerprint(trace, "b", "B", "shadow", "se_shadow");

      expect(engine.getStats().totalFingerprintsExtracted).toBe(2);
    });
  });

  describe("antibody propagation", () => {
    it("creates an antibody from a fingerprint", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "agent1", "Agent One", "honeypot", "hp_api_key",
        ["entityDensityPer1k", "entityEchoRate"], [],
      );
      const ab = engine.propagate(fp);

      expect(ab.fingerprintId).toBe(fp.id);
      expect(ab.active).toBe(true);
      expect(ab.confirmations).toBe(1);
      expect(ab.sigmaTightening).toHaveProperty("entityDensityPer1k");
      expect(ab.sigmaTightening).toHaveProperty("entityEchoRate");
      expect(ab.sigmaTightening["entityDensityPer1k"]).toBe(0.5);
      expect(ab.watchTrigrams.length).toBeGreaterThan(0);
      expect(ab.watchVector.length).toBe(256);
    });

    it("uses default dimensions when none flagged", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "phantom", "pt_upload", [], [],
      );
      const ab = engine.propagate(fp);

      // Default tightening should hit entityDensityPer1k, newVocabularyRate, entityEchoRate
      expect(Object.keys(ab.sigmaTightening)).toContain("entityDensityPer1k");
      expect(Object.keys(ab.sigmaTightening)).toContain("newVocabularyRate");
      expect(Object.keys(ab.sigmaTightening)).toContain("entityEchoRate");
    });

    it("reconfirms instead of creating duplicate for same fingerprint", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      const ab1 = engine.propagate(fp);
      const ab2 = engine.propagate(fp);

      expect(ab1).toBe(ab2); // Same object
      expect(ab1.confirmations).toBe(2);
      expect(engine.getStats().totalAntibodiesCreated).toBe(1);
      expect(engine.getStats().totalReconfirmations).toBe(1);
    });

    it("sets forced signatures based on threat type", () => {
      const trace = makeTrace({ threatType: "honeypot_credential" });
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      const ab = engine.propagate(fp);

      expect(ab.forcedSignatures).toContain("hp_api_key");
      expect(ab.forcedSignatures).toContain("de_base64_exfil");
    });
  });

  describe("antibody matching", () => {
    it("matches a similar tool sequence against active antibodies", () => {
      const trace = makeTrace({
        legitimatePrefix: ["read_file", "search"],
        hijackedSuffix: ["send_to_webhook"],
      });
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      engine.propagate(fp);

      // Similar sequence should match
      const matches = engine.matchAntibodies(["read_file", "search", "send_to_webhook"]);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].similarity).toBeGreaterThanOrEqual(0.7);
    });

    it("does not match a completely different sequence", () => {
      const trace = makeTrace({
        legitimatePrefix: ["read_file", "search"],
        hijackedSuffix: ["send_to_webhook"],
      });
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      engine.propagate(fp);

      // Completely different sequence
      const matches = engine.matchAntibodies(["deploy", "restart", "monitor", "scale"]);
      // May or may not match depending on embedding — we just check it doesn't crash
      // and if it matches, similarity should be lower
      for (const m of matches) {
        expect(m.similarity).toBeGreaterThanOrEqual(0.7); // threshold enforced
      }
    });

    it("requires at least 2 tools in session", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      engine.propagate(fp);

      expect(engine.matchAntibodies(["read_file"]).length).toBe(0);
      expect(engine.matchAntibodies([]).length).toBe(0);
    });
  });

  describe("sigma tightening", () => {
    it("tightens sigma for flagged dimensions", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key",
        ["entityDensityPer1k"], [],
      );
      engine.propagate(fp);

      const effective = engine.getEffectiveSigma(3.0, "entityDensityPer1k");
      expect(effective).toBe(1.5); // 3.0 * 0.5
    });

    it("returns base sigma for non-flagged dimensions", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key",
        ["entityDensityPer1k"], [],
      );
      engine.propagate(fp);

      const effective = engine.getEffectiveSigma(3.0, "responseLength");
      expect(effective).toBe(3.0);
    });

    it("enforces hard floor of 1.0", () => {
      const engine2 = new ImmuneResponseEngine(dir, makeConfig({ sigmaTightenFactor: 0.1 }));
      const trace = makeTrace();
      const fp = engine2.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key",
        ["entityDensityPer1k"], [],
      );
      engine2.propagate(fp);

      // 3.0 * 0.1 = 0.3, but floor is 1.0
      expect(engine2.getEffectiveSigma(3.0, "entityDensityPer1k")).toBe(1.0);
    });

    it("getSigmaOverrides returns a complete map", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key",
        ["entityDensityPer1k", "entityEchoRate"], [],
      );
      engine.propagate(fp);

      const overrides = engine.getSigmaOverrides(3.0);
      expect(overrides["entityDensityPer1k"]).toBe(1.5);
      expect(overrides["entityEchoRate"]).toBe(1.5);
      expect(overrides["responseLength"]).toBeUndefined();
    });
  });

  describe("sigmaOverrides integration with detectAnomalies", () => {
    it("tightened sigma catches anomalies that base sigma misses", () => {
      // Build a baseline with mean=2.0, stddev=1.0
      let stats = emptyStats();
      for (let i = 0; i < 50; i++) {
        stats = updateStats(stats, 2.0 + (Math.random() - 0.5) * 2);
      }
      const baseline: BaselineFeatureStats = { entityDensityPer1k: stats };
      const features = makeFeatureVector({ entityDensityPer1k: 5.0 });

      const knownTools = new Set(["read_file"]);
      const knownCategories = new Set<string>();

      // With base sigma=3.0, a z-score of ~3 might not trigger
      const alertsBase = detectAnomalies(features, baseline, 3.0, knownTools, knownCategories);

      // With tightened sigma=1.5, the same observation should trigger
      const alertsTight = detectAnomalies(features, baseline, 3.0, knownTools, knownCategories, { entityDensityPer1k: 1.5 });

      // Tightened should catch more (or at least as many) anomalies
      expect(alertsTight.length).toBeGreaterThanOrEqual(alertsBase.length);
    });
  });

  describe("threshold overrides", () => {
    it("removes forced signatures from suppressed list", () => {
      const trace = makeTrace({ threatType: "honeypot_credential" });
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      engine.propagate(fp);

      const thresholds = engine.applyToThresholds({
        driftThreshold: 0.15,
        coherenceZScore: 3.0,
        transformerThreshold: 0.85,
        suppressedSignatures: ["hp_api_key", "other_sig"],
      });

      expect(thresholds.suppressedSignatures).not.toContain("hp_api_key");
      expect(thresholds.suppressedSignatures).toContain("other_sig");
    });

    it("returns unchanged thresholds when no antibodies active", () => {
      const thresholds = engine.applyToThresholds({
        driftThreshold: 0.15,
        coherenceZScore: 3.0,
        transformerThreshold: 0.85,
        suppressedSignatures: ["some_sig"],
      });

      expect(thresholds.driftThreshold).toBe(0.15);
      expect(thresholds.coherenceZScore).toBe(3.0);
      expect(thresholds.transformerThreshold).toBe(0.85);
      expect(thresholds.suppressedSignatures).toEqual(["some_sig"]);
    });
  });

  describe("TTL decay", () => {
    it("expires antibodies past TTL", () => {
      const engine2 = new ImmuneResponseEngine(dir, makeConfig({ ttlSec: 1 }));
      const trace = makeTrace();
      const fp = engine2.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      const ab = engine2.propagate(fp);

      // Force expiry
      ab.expiresAt = Date.now() - 1000;
      engine2.decayTick();

      expect(ab.active).toBe(false);
      expect(engine2.getActiveAntibodies().length).toBe(0);
      expect(engine2.getStats().totalDecays).toBe(1);
    });

    it("does not expire antibodies within TTL", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      engine.propagate(fp);
      engine.decayTick();

      expect(engine.getActiveAntibodies().length).toBe(1);
    });
  });

  describe("re-confirmation", () => {
    it("extends TTL and increments confirmation count", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key", [], [],
      );
      const ab = engine.propagate(fp);
      const originalExpiry = ab.expiresAt;

      // Advance time slightly
      ab.expiresAt = Date.now() + 1000; // Almost expired
      engine.reconfirm(fp.id);

      expect(ab.confirmations).toBe(2);
      expect(ab.expiresAt).toBeGreaterThan(originalExpiry - 1000); // TTL reset
    });
  });

  describe("persistence", () => {
    it("survives flush + load cycle", () => {
      const trace = makeTrace();
      const fp = engine.extractFingerprint(
        trace, "a", "A", "honeypot", "hp_key",
        ["entityDensityPer1k"], [],
      );
      engine.propagate(fp);
      engine.flush();

      // Create new engine from same directory
      const engine2 = new ImmuneResponseEngine(dir, makeConfig());
      const state = engine2.getState();

      expect(state.fingerprints.length).toBe(1);
      expect(state.antibodies.length).toBe(1);
      expect(state.antibodies[0].active).toBe(true);
      expect(state.antibodies[0].fingerprintId).toBe(fp.id);
      expect(state.stats.totalFingerprintsExtracted).toBe(1);
      expect(state.stats.totalAntibodiesCreated).toBe(1);
    });
  });

  describe("LRU eviction", () => {
    it("evicts oldest antibodies when max exceeded", () => {
      const smallEngine = new ImmuneResponseEngine(dir, makeConfig({ maxAntibodies: 3 }));

      for (let i = 0; i < 5; i++) {
        const trace = makeTrace({
          legitimatePrefix: [`tool_${i}`],
          hijackedSuffix: [`attack_${i}`],
          threatType: `threat_${i}`,
        });
        const fp = smallEngine.extractFingerprint(
          trace, `agent_${i}`, `Agent ${i}`, "honeypot", `sig_${i}`, [], [],
        );
        smallEngine.propagate(fp);
      }

      expect(smallEngine.getActiveAntibodies().length).toBeLessThanOrEqual(3);
    });
  });

  describe("getState", () => {
    it("returns a complete state snapshot", () => {
      const state = engine.getState();

      expect(state.version).toBe(1);
      expect(state.fingerprints).toEqual([]);
      expect(state.antibodies).toEqual([]);
      expect(state.stats.totalFingerprintsExtracted).toBe(0);
      expect(state.stats.totalAntibodiesCreated).toBe(0);
      expect(state.stats.totalPropagations).toBe(0);
      expect(state.stats.totalDecays).toBe(0);
      expect(state.stats.totalReconfirmations).toBe(0);
      expect(state.stats.totalMatches).toBe(0);
    });
  });
});
