/**
 * Tests for intent attention extraction and hijack detection.
 *
 * The transformer projects user intent into position 0 via a learned projection.
 * All tool tokens attend to this via self-attention. When attention to position 0
 * drops near zero, it signals the agent has been hijacked away from the user's request.
 */

import { describe, test, expect, beforeEach } from "vitest";
import { MiniTransformer, DEFAULT_CONFIG } from "../src/transformer/model.js";
import { TransformerScorer, DEFAULT_SCORER_CONFIG } from "../src/transformer/scorer.js";
import { ThreatClass } from "../src/security-event.js";
import { ToolTokenizer } from "../src/transformer/tokenizer.js";
import { TransformerTrainer } from "../src/transformer/trainer.js";

// ─── ForwardCache: intentAttention extraction ───

describe("intentAttention in ForwardCache", () => {
  let model: MiniTransformer;

  beforeEach(() => {
    model = new MiniTransformer(DEFAULT_CONFIG);
    model.initWeights("test-intent-attn");
  });

  test("intentAttention array is present and correctly sized", () => {
    const tokenIds = [2, 4, 5, 6]; // BOS + 3 tools
    const cache = model.forwardFull(tokenIds);
    // numLayers=2, numHeads=4 → 8 values
    expect(cache.intentAttention).toBeInstanceOf(Float64Array);
    expect(cache.intentAttention.length).toBe(8);
  });

  test("intentAttention values are valid probabilities (0-1)", () => {
    const tokenIds = [2, 4, 5, 6, 7];
    const cache = model.forwardFull(tokenIds);
    for (let i = 0; i < cache.intentAttention.length; i++) {
      expect(cache.intentAttention[i]).toBeGreaterThanOrEqual(0);
      expect(cache.intentAttention[i]).toBeLessThanOrEqual(1);
    }
  });

  test("with intent vector, position 0 gets non-zero attention", () => {
    const tokenIds = [2, 4, 5, 6, 7, 8];
    // Create a non-zero intent vector (256 dims)
    const intentVec = new Float64Array(256);
    for (let i = 0; i < 256; i++) intentVec[i] = Math.sin(i * 0.1) * 0.5;

    const cache = model.forwardFull(tokenIds, intentVec);
    // At least some heads should attend to position 0 with non-trivial weight
    const avgAttn = Array.from(cache.intentAttention).reduce((a, b) => a + b, 0) / cache.intentAttention.length;
    // With a projected intent vector in position 0, attention should be > 0
    // (model is freshly initialized, so attention is spread somewhat uniformly;
    //  with 6 positions, uniform would be ~1/6 ≈ 0.167)
    expect(avgAttn).toBeGreaterThan(0);
  });

  test("without intent vector, position 0 still gets some attention (BOS token)", () => {
    const tokenIds = [2, 4, 5, 6, 7];
    const cache = model.forwardFull(tokenIds);
    // Even without intent, BOS at position 0 gets some attention
    const avgAttn = Array.from(cache.intentAttention).reduce((a, b) => a + b, 0) / cache.intentAttention.length;
    expect(avgAttn).toBeGreaterThan(0);
  });

  test("intentAttention tracks position 0 correctly for single-token sequence", () => {
    // With sequence length 1, last position IS position 0 → attention to self = 1.0
    const tokenIds = [2]; // just BOS
    const cache = model.forwardFull(tokenIds);
    // Each head at last pos (pos 0) attending to pos 0 should be 1.0 (only option)
    for (let i = 0; i < cache.intentAttention.length; i++) {
      expect(cache.intentAttention[i]).toBeCloseTo(1.0, 5);
    }
  });

  test("intentAttention layout matches headAttentionEntropy layout", () => {
    const tokenIds = [2, 4, 5, 6];
    const cache = model.forwardFull(tokenIds);
    // Both should be numLayers * numHeads = 8
    expect(cache.intentAttention.length).toBe(cache.headAttentionEntropy.length);
    expect(cache.intentAttention.length).toBe(DEFAULT_CONFIG.numLayers * DEFAULT_CONFIG.numHeads);
  });
});

// ─── Scorer: intentAttention in ToolPrediction ───

describe("intentAttention in scorer", () => {
  let scorer: TransformerScorer;

  beforeEach(() => {
    scorer = new TransformerScorer("/tmp/shroud-test-intent-attn-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      minSequenceLength: 2,
      intentAttentionThreshold: 0.05,
    });
  });

  test("cold start returns zero intentAttention", () => {
    const prediction = scorer.scoreToolCall(["tool_a"], "tool_b");
    expect(prediction.intentAttention).toBe(0);
    expect(prediction.intentAttentionPerHead).toEqual([]);
  });

  test("trained model returns intentAttention and per-head breakdown", () => {
    // Train a minimal model by manually training the scorer
    const scorerDir = "/tmp/shroud-test-intent-trained-" + Date.now();
    const trainedScorer = new TransformerScorer(scorerDir, {
      ...DEFAULT_SCORER_CONFIG, minSequenceLength: 2, intentAttentionThreshold: 0.05,
    });

    // Manually train the model
    const model = (trainedScorer as any)._model as MiniTransformer;
    const tok = (trainedScorer as any)._tokenizer as ToolTokenizer;
    tok.addTool("read_file"); tok.addTool("edit_file"); tok.addTool("write_file"); tok.addTool("run_test");
    model.initWeights("scorer-intent-test");

    const trainer = new TransformerTrainer(model, tok, {
      learningRate: 0.01, minLearningRate: 0.001,
      batchSize: 4, maxEpochs: 30, warmupSteps: 5,
      maxSequences: 100, gradClipNorm: 1.0,
    });
    trainer.trainOnSequences(Array(30).fill(["read_file", "edit_file", "write_file", "run_test"]));
    (trainedScorer as any)._modelLoaded = true;

    const prediction = trainedScorer.scoreToolCall(
      ["read_file", "edit_file", "write_file"],
      "run_test",
    );

    expect(prediction.intentAttention).toBeGreaterThanOrEqual(0);
    expect(prediction.intentAttentionPerHead.length).toBe(8); // 4 heads x 2 layers
    // Each per-head value should be a valid probability
    for (const v of prediction.intentAttentionPerHead) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
});

// ─── Anomaly detection: INTENT_HIJACK ───

describe("intent hijack anomaly detection", () => {
  test("INTENT_HIJACK exists in ThreatClass enum", () => {
    expect(ThreatClass.INTENT_HIJACK).toBe("intent_hijack");
  });

  test("checkAnomaly fires INTENT_HIJACK when intentAttention below threshold", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-hijack-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    const prediction = {
      topK: [{ tool: "read_file", prob: 0.3 }],
      surprise: 0.5, // below anomaly threshold, so surprise won't fire
      perplexity: 2,
      sessionAnomalyScore: 0.3,
      embeddingShift: 0.1,
      threatPrediction: null,
      intentAttention: 0.02, // below 0.05 threshold
      intentAttentionPerHead: [0.01, 0.02, 0.03, 0.01, 0.02, 0.03, 0.01, 0.03],
    };

    const event = scorer.checkAnomaly(prediction, "exfil_data", "test-agent");
    expect(event).not.toBeNull();
    expect(event!.threatClass).toBe(ThreatClass.INTENT_HIJACK);
    expect(event!.signatureId).toBe("transformer_intent_hijack");
    expect(event!.description).toContain("intent");
    expect(event!.agentLabel).toBe("test-agent");
  });

  test("checkAnomaly does NOT fire when intentAttention above threshold", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-no-hijack-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    const prediction = {
      topK: [{ tool: "read_file", prob: 0.8 }],
      surprise: 0.2,
      perplexity: 1.2,
      sessionAnomalyScore: 0.1,
      embeddingShift: 0.05,
      threatPrediction: null,
      intentAttention: 0.15, // above threshold
      intentAttentionPerHead: [0.1, 0.2, 0.15, 0.12, 0.18, 0.14, 0.11, 0.2],
    };

    const event = scorer.checkAnomaly(prediction, "read_file");
    expect(event).toBeNull();
  });

  test("checkAnomaly returns high severity when intentAttention < 0.01", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-hijack-high-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    const prediction = {
      topK: [],
      surprise: 0.5,
      perplexity: 2,
      sessionAnomalyScore: 0.3,
      embeddingShift: 0.1,
      threatPrediction: null,
      intentAttention: 0.005, // very low
      intentAttentionPerHead: [0.001, 0.002, 0.008, 0.005, 0.003, 0.007, 0.006, 0.008],
    };

    const event = scorer.checkAnomaly(prediction, "curl_upload");
    expect(event).not.toBeNull();
    expect(event!.severity).toBe("high");
  });

  test("checkAnomaly returns medium severity when intentAttention between 0.01 and threshold", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-hijack-medium-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    const prediction = {
      topK: [],
      surprise: 0.5,
      perplexity: 2,
      sessionAnomalyScore: 0.3,
      embeddingShift: 0.1,
      threatPrediction: null,
      intentAttention: 0.03, // between 0.01 and 0.05
      intentAttentionPerHead: [0.02, 0.03, 0.04, 0.03, 0.02, 0.04, 0.03, 0.03],
    };

    const event = scorer.checkAnomaly(prediction, "strange_tool");
    expect(event).not.toBeNull();
    expect(event!.severity).toBe("medium");
  });

  test("checkAnomaly skips intent check when intentAttentionPerHead is empty", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-hijack-empty-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    // Cold start — no per-head data
    const prediction = {
      topK: [],
      surprise: 0.5,
      perplexity: 2,
      sessionAnomalyScore: 0.3,
      embeddingShift: 0.1,
      threatPrediction: null,
      intentAttention: 0,
      intentAttentionPerHead: [], // empty = no model output
    };

    const event = scorer.checkAnomaly(prediction, "any_tool");
    // Should not fire intent hijack (no data), and surprise is below threshold
    expect(event).toBeNull();
  });
});

// ─── Session-level intent attention tracking ───

describe("session-level intent attention tracking", () => {
  test("recentIntentAttention appears in getStats", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-stats-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    const stats = scorer.getStats();
    expect(stats).toHaveProperty("recentIntentAttention");
    expect(Array.isArray(stats.recentIntentAttention)).toBe(true);
    expect(stats.recentIntentAttention.length).toBe(0); // no scoring yet
  });

  test("resetSession clears intent attention window", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-reset-" + Date.now(), {
      ...DEFAULT_SCORER_CONFIG,
      intentAttentionThreshold: 0.05,
    });

    // Score something (cold start, won't accumulate, but resetSession should still work)
    scorer.resetSession();
    const stats = scorer.getStats();
    expect(stats.recentIntentAttention.length).toBe(0);
    expect(stats.recentSurprises.length).toBe(0);
  });
});
