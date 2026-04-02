/**
 * Threat head classifier + self-labeling flywheel tests (Tier 4).
 *
 * Tests:
 * - Attention entropy computation
 * - ThreatHeadClassifier forward pass shapes
 * - ThreatHeadClassifier backward/training
 * - SelfLabelingFlywheel label generation for each trigger type
 * - Serialization round-trip of threat head weights
 * - End-to-end: train threat heads, verify classification improves
 * - Aggregation layer reliability weighting
 */

import { describe, test, expect, beforeEach } from "vitest";
import {
  ThreatHeadClassifier,
  LearnedThreatClass,
  LEARNED_THREAT_CLASS_COUNT,
  THREAT_HEAD_NAMES,
  attentionEntropy,
  type ThreatPrediction,
  type ThreatLabeledExample,
} from "../src/transformer/threat-heads.js";
import { SelfLabelingFlywheel } from "../src/transformer/flywheel.js";
import { MiniTransformer, DEFAULT_CONFIG } from "../src/transformer/model.js";
import { ToolTokenizer } from "../src/transformer/tokenizer.js";
import { TransformerTrainer } from "../src/transformer/trainer.js";
import { entropy } from "../src/transformer/linalg.js";

// ─── Entropy ───

describe("linalg entropy", () => {
  test("entropy of uniform distribution", () => {
    const p = new Float64Array([0.25, 0.25, 0.25, 0.25]);
    const h = entropy(p, 4);
    expect(h).toBeCloseTo(Math.log(4), 5);
  });

  test("entropy of deterministic distribution is zero", () => {
    const p = new Float64Array([1, 0, 0, 0]);
    expect(entropy(p, 4)).toBeCloseTo(0, 10);
  });

  test("entropy of binary distribution", () => {
    const p = new Float64Array([0.5, 0.5]);
    expect(entropy(p, 2)).toBeCloseTo(Math.log(2), 5);
  });

  test("entropy handles near-zero probabilities", () => {
    const p = new Float64Array([1e-15, 1 - 1e-15]);
    expect(entropy(p, 2)).toBeGreaterThanOrEqual(0);
    expect(entropy(p, 2)).toBeLessThan(0.001);
  });
});

// ─── Attention Entropy ───

describe("attentionEntropy", () => {
  test("computes correct shape", () => {
    // 2 layers, 4 heads, seqLen=3
    const numHeads = 4;
    const numLayers = 2;
    const seqLen = 3;
    // Each layer's attnWeights: numHeads × seqLen × seqLen
    const layer0 = new Float64Array(numHeads * seqLen * seqLen);
    const layer1 = new Float64Array(numHeads * seqLen * seqLen);

    // Fill with uniform attention for simplicity
    for (let h = 0; h < numHeads; h++) {
      for (let i = 0; i < seqLen; i++) {
        for (let j = 0; j <= i; j++) {
          // Uniform over valid (causal) positions
          const prob = 1 / (i + 1);
          layer0[h * seqLen * seqLen + i * seqLen + j] = prob;
          layer1[h * seqLen * seqLen + i * seqLen + j] = prob;
        }
      }
    }

    const result = attentionEntropy([layer0, layer1], numHeads, numLayers, seqLen);
    expect(result.length).toBe(numHeads * numLayers); // 8

    // At last position (seqLen-1=2), uniform over 3 positions => entropy = log(3)
    for (let i = 0; i < result.length; i++) {
      expect(result[i]).toBeCloseTo(Math.log(3), 5);
    }
  });

  test("focused attention has low entropy", () => {
    const numHeads = 4;
    const numLayers = 2;
    const seqLen = 5;
    const layer0 = new Float64Array(numHeads * seqLen * seqLen);
    const layer1 = new Float64Array(numHeads * seqLen * seqLen);

    // Head 0: focused attention on position 0 at last position
    const lastPos = seqLen - 1;
    layer0[0 * seqLen * seqLen + lastPos * seqLen + 0] = 0.95;
    for (let j = 1; j <= lastPos; j++) {
      layer0[0 * seqLen * seqLen + lastPos * seqLen + j] = 0.05 / lastPos;
    }

    // Head 1: uniform
    for (let j = 0; j <= lastPos; j++) {
      layer0[1 * seqLen * seqLen + lastPos * seqLen + j] = 1 / (lastPos + 1);
    }

    // Fill remaining for layer1
    for (let h = 0; h < numHeads; h++) {
      for (let j = 0; j <= lastPos; j++) {
        layer1[h * seqLen * seqLen + lastPos * seqLen + j] = 1 / (lastPos + 1);
      }
    }

    const result = attentionEntropy([layer0, layer1], numHeads, numLayers, seqLen);

    // Head 0 layer 0: low entropy (focused)
    expect(result[0]).toBeLessThan(0.5);
    // Head 1 layer 0: high entropy (uniform over 5)
    expect(result[1]).toBeCloseTo(Math.log(5), 1);
  });
});

// ─── ThreatHeadClassifier ───

describe("ThreatHeadClassifier", () => {
  let classifier: ThreatHeadClassifier;

  beforeEach(() => {
    classifier = new ThreatHeadClassifier();
    classifier.initWeights("test-seed");
  });

  test("forward pass returns correct shapes", () => {
    const backbone = new Float64Array(64);
    backbone[0] = 1.0;
    const headEntropy = new Float64Array(8);
    headEntropy.fill(0.5);

    const pred = classifier.forward(backbone, headEntropy);
    expect(pred.heads.length).toBe(3);

    for (const h of pred.heads) {
      expect(h.distribution.length).toBe(LEARNED_THREAT_CLASS_COUNT);
      // Probabilities should sum to 1
      const sum = Array.from(h.distribution).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1, 5);
    }

    expect(pred.reliabilityWeights.length).toBe(3);
    const relSum = Array.from(pred.reliabilityWeights).reduce((a, b) => a + b, 0);
    expect(relSum).toBeCloseTo(1, 5);

    expect(typeof pred.threatScore).toBe("number");
    expect(pred.threatScore).toBeGreaterThanOrEqual(0);
    expect(pred.threatScore).toBeLessThanOrEqual(1);
  });

  test("forward pass head names match", () => {
    const backbone = new Float64Array(64);
    const headEntropy = new Float64Array(8);
    const pred = classifier.forward(backbone, headEntropy);
    expect(pred.heads.map(h => h.name)).toEqual(THREAT_HEAD_NAMES);
  });

  test("backward pass returns correct shapes", () => {
    const backbone = new Float64Array(64);
    backbone[0] = 1.0;
    const headEntropy = new Float64Array(8);
    headEntropy.fill(0.5);

    const cache = classifier.forwardWithCache(0, backbone, headEntropy);
    const grad = classifier.backwardHead(0, cache, LearnedThreatClass.HOSTILE);

    expect(grad.w1.length).toBe(72 * 16);
    expect(grad.b1.length).toBe(16);
    expect(grad.w2.length).toBe(16 * 4);
    expect(grad.b2.length).toBe(4);
  });

  test("backward produces non-zero gradients", () => {
    const backbone = new Float64Array(64);
    for (let i = 0; i < 64; i++) backbone[i] = Math.sin(i);
    const headEntropy = new Float64Array(8);
    for (let i = 0; i < 8; i++) headEntropy[i] = 0.3 + i * 0.1;

    const cache = classifier.forwardWithCache(0, backbone, headEntropy);
    const grad = classifier.backwardHead(0, cache, LearnedThreatClass.ALIGNED);

    let hasNonZero = false;
    for (let i = 0; i < grad.w1.length; i++) {
      if (Math.abs(grad.w1[i]) > 1e-10) { hasNonZero = true; break; }
    }
    expect(hasNonZero).toBe(true);
  });

  test("training reduces loss", () => {
    const backbone = new Float64Array(64);
    for (let i = 0; i < 64; i++) backbone[i] = Math.sin(i);
    const headEntropy = new Float64Array(8);
    headEntropy.fill(0.5);

    // Initial loss
    const cache0 = classifier.forwardWithCache(0, backbone, headEntropy);
    const loss0 = -Math.log(Math.max(cache0.probs[LearnedThreatClass.HOSTILE], 1e-12));

    // Train for a few steps
    const lr = 0.01;
    for (let step = 0; step < 50; step++) {
      const cache = classifier.forwardWithCache(0, backbone, headEntropy);
      const grad = classifier.backwardHead(0, cache, LearnedThreatClass.HOSTILE);
      const head = classifier.weights.heads[0];
      for (let i = 0; i < grad.w1.length; i++) head.w1[i] -= lr * grad.w1[i];
      for (let i = 0; i < grad.b1.length; i++) head.b1[i] -= lr * grad.b1[i];
      for (let i = 0; i < grad.w2.length; i++) head.w2[i] -= lr * grad.w2[i];
      for (let i = 0; i < grad.b2.length; i++) head.b2[i] -= lr * grad.b2[i];
    }

    // Final loss should be lower
    const cacheF = classifier.forwardWithCache(0, backbone, headEntropy);
    const lossF = -Math.log(Math.max(cacheF.probs[LearnedThreatClass.HOSTILE], 1e-12));
    expect(lossF).toBeLessThan(loss0);
  });

  test("paramCount is approximately 3714", () => {
    // 3 heads × (72*16 + 16 + 16*4 + 4) + 3 reliability = 3 × 1236 + 3 = 3711
    const count = classifier.paramCount();
    expect(count).toBe(3711);
  });
});

// ─── Serialization ───

describe("ThreatHeadClassifier serialization", () => {
  test("round-trip preserves weights", () => {
    const classifier = new ThreatHeadClassifier();
    classifier.initWeights("serial-test");

    const data = classifier.serialize();
    expect(data.length).toBe(classifier.paramCount());

    const restored = new ThreatHeadClassifier();
    restored.deserialize(data);

    // Check weights match
    for (let h = 0; h < 3; h++) {
      for (let i = 0; i < classifier.weights.heads[h].w1.length; i++) {
        expect(restored.weights.heads[h].w1[i]).toBe(classifier.weights.heads[h].w1[i]);
      }
      for (let i = 0; i < classifier.weights.heads[h].w2.length; i++) {
        expect(restored.weights.heads[h].w2[i]).toBe(classifier.weights.heads[h].w2[i]);
      }
    }
    for (let i = 0; i < 3; i++) {
      expect(restored.weights.reliability[i]).toBe(classifier.weights.reliability[i]);
    }
  });

  test("serialized data has correct length", () => {
    const classifier = new ThreatHeadClassifier();
    classifier.initWeights();
    const data = classifier.serialize();
    expect(data.length).toBe(classifier.paramCount());
  });
});

// ─── Aggregation / Reliability ───

describe("reliability weighting", () => {
  test("equal reliability gives equal weights", () => {
    const classifier = new ThreatHeadClassifier();
    classifier.initWeights();
    // All reliability = 1.0 (default after init)
    const backbone = new Float64Array(64);
    const headEntropy = new Float64Array(8);
    const pred = classifier.forward(backbone, headEntropy);
    // Equal reliability → softmax → ~1/3 each
    for (let i = 0; i < 3; i++) {
      expect(pred.reliabilityWeights[i]).toBeCloseTo(1 / 3, 2);
    }
  });

  test("updateReliability changes weights", () => {
    const classifier = new ThreatHeadClassifier();
    classifier.initWeights();

    // Make head 0 more reliable
    for (let i = 0; i < 50; i++) {
      classifier.updateReliability(0, true);
      classifier.updateReliability(1, false);
      classifier.updateReliability(2, false);
    }

    const backbone = new Float64Array(64);
    const headEntropy = new Float64Array(8);
    const pred = classifier.forward(backbone, headEntropy);

    // Head 0 should have highest reliability weight
    expect(pred.reliabilityWeights[0]).toBeGreaterThan(pred.reliabilityWeights[1]);
    expect(pred.reliabilityWeights[0]).toBeGreaterThan(pred.reliabilityWeights[2]);
  });
});

// ─── SelfLabelingFlywheel ───

describe("SelfLabelingFlywheel", () => {
  let flywheel: SelfLabelingFlywheel;

  beforeEach(() => {
    flywheel = new SelfLabelingFlywheel();
  });

  test("onHoneypotTrigger — webhook_url maps to exfil HOSTILE", () => {
    const result = flywheel.onHoneypotTrigger(
      "webhook_url",
      ["read_file", "grep", "web_fetch", "malicious_upload"],
      2,
    );

    expect(result.trace.source).toBe("honeypot");
    expect(result.trace.threatType).toBe("honeypot_webhook_url");
    expect(result.labels.length).toBeGreaterThanOrEqual(1);

    // Attack sequence label
    const attackLabel = result.labels[0];
    expect(attackLabel.headLabels[0]).toBe(LearnedThreatClass.HOSTILE); // exfil
    expect(attackLabel.headLabels[1]).toBe(LearnedThreatClass.ALIGNED); // privesc
    expect(attackLabel.headLabels[2]).toBe(LearnedThreatClass.ALIGNED); // recon
  });

  test("onHoneypotTrigger — api_key maps to exfil HOSTILE", () => {
    const result = flywheel.onHoneypotTrigger(
      "api_key",
      ["read_file", "bash", "web_fetch"],
      1,
    );
    const attackLabel = result.labels[0];
    expect(attackLabel.headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onHoneypotTrigger — hostname maps to recon SUSPICIOUS + exfil HOSTILE", () => {
    const result = flywheel.onHoneypotTrigger(
      "hostname",
      ["bash", "grep", "web_fetch"],
      1,
    );
    const attackLabel = result.labels[0];
    expect(attackLabel.headLabels[0]).toBe(LearnedThreatClass.HOSTILE);    // exfil
    expect(attackLabel.headLabels[2]).toBe(LearnedThreatClass.SUSPICIOUS); // recon
  });

  test("onHoneypotTrigger produces ALIGNED label for legitimate prefix", () => {
    const result = flywheel.onHoneypotTrigger(
      "email",
      ["read_file", "grep", "web_fetch"],
      2,
    );
    // Should have legitimate prefix label
    const alignedLabel = result.labels.find(l =>
      l.headLabels.every(h => h === LearnedThreatClass.ALIGNED),
    );
    expect(alignedLabel).toBeDefined();
    expect(alignedLabel!.sequence.length).toBe(2); // prefix before injection
  });

  test("onPhantomTrigger — data_upload maps to exfil HOSTILE", () => {
    const result = flywheel.onPhantomTrigger(
      "data_upload",
      ["read_file", "grep", "shroud_upload_data"],
    );
    expect(result.trace.source).toBe("phantom");
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onPhantomTrigger — webhook_relay maps to exfil HOSTILE", () => {
    const result = flywheel.onPhantomTrigger(
      "webhook_relay",
      ["read_file", "shroud_webhook_relay"],
    );
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onPhantomTrigger — email_forward maps to exfil HOSTILE", () => {
    const result = flywheel.onPhantomTrigger(
      "email_forward",
      ["bash", "read_file", "shroud_email_forward"],
    );
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onPhantomTrigger — api_relay maps to exfil HOSTILE", () => {
    const result = flywheel.onPhantomTrigger(
      "api_relay",
      ["bash", "shroud_api_relay"],
    );
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onPhantomTrigger — file_export maps to exfil HOSTILE", () => {
    const result = flywheel.onPhantomTrigger(
      "file_export",
      ["read_file", "shroud_file_export"],
    );
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE);
  });

  test("onShadowBlock — egress in reason maps to exfil HOSTILE", () => {
    const result = flywheel.onShadowBlock(
      "Blocked: egress to external server detected",
      ["read_file", "bash"],
      ["web_fetch", "curl"],
    );
    expect(result.trace.source).toBe("shadow");
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.HOSTILE); // exfil
  });

  test("onShadowBlock — sensitive path maps to recon + exfil", () => {
    const result = flywheel.onShadowBlock(
      "Blocked: access to sensitive path /etc/shadow",
      ["bash"],
      ["read_file"],
    );
    const attackLabel = result.labels[0];
    expect(attackLabel.headLabels[0]).toBe(LearnedThreatClass.HOSTILE);    // exfil
    expect(attackLabel.headLabels[2]).toBe(LearnedThreatClass.SUSPICIOUS); // recon
  });

  test("onShadowBlock — generic reason maps to SUSPICIOUS", () => {
    const result = flywheel.onShadowBlock(
      "Blocked: unexpected behavior",
      ["read_file", "bash"],
      ["exec"],
    );
    expect(result.labels[0].headLabels[0]).toBe(LearnedThreatClass.SUSPICIOUS);
  });

  test("onHealthyWorkflow produces all ALIGNED labels", () => {
    const label = flywheel.onHealthyWorkflow(["read_file", "grep", "write_file"]);
    expect(label).not.toBeNull();
    expect(label!.headLabels).toEqual([
      LearnedThreatClass.ALIGNED,
      LearnedThreatClass.ALIGNED,
      LearnedThreatClass.ALIGNED,
    ]);
  });

  test("onHealthyWorkflow rejects short sequences", () => {
    expect(flywheel.onHealthyWorkflow(["read_file"])).toBeNull();
    expect(flywheel.onHealthyWorkflow([])).toBeNull();
  });
});

// ─── End-to-End: Train + Classify ───

describe("end-to-end threat head training", () => {
  test("training on labeled examples improves classification", async () => {
    const model = new MiniTransformer(DEFAULT_CONFIG);
    model.initWeights("e2e-test");
    const tokenizer = new ToolTokenizer();

    const classifier = new ThreatHeadClassifier();
    classifier.initWeights("e2e-test");

    // Build training examples
    const examples: ThreatLabeledExample[] = [];

    // Healthy workflows → all ALIGNED
    for (let i = 0; i < 20; i++) {
      examples.push({
        sequence: ["read_file", "grep", "write_file"],
        intentVec: null,
        headLabels: [LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED],
      });
    }

    // Attack workflows → exfil HOSTILE
    for (let i = 0; i < 20; i++) {
      examples.push({
        sequence: ["read_file", "web_fetch", "bash"],
        intentVec: null,
        headLabels: [LearnedThreatClass.HOSTILE, LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED],
      });
    }

    // Get initial exfil head confidence on attack sequence
    const attackIds = tokenizer.encodeSequence(["read_file", "web_fetch", "bash"]);
    const initialCache = model.forwardFull(attackIds, null);
    const initialPred = classifier.forward(initialCache.finalLnOut, initialCache.headAttentionEntropy);
    const initialHostile = initialPred.heads[0].distribution[LearnedThreatClass.HOSTILE];

    // Train via trainer (which calls _trainThreatHeads internally)
    const healthySeqs = [
      ["read_file", "grep", "write_file"],
      ["bash", "read_file", "edit"],
      ["glob", "grep", "read_file"],
    ];
    const trainer = new TransformerTrainer(model, tokenizer);
    const result = await trainer.trainOnSequences(
      healthySeqs,
      undefined,
      undefined,
      classifier,
      examples,
    );

    expect(result.threatHeadLoss).toBeGreaterThan(0);

    // After training, exfil head should be more confident on attack sequence
    const afterCache = model.forwardFull(attackIds, null);
    const afterPred = classifier.forward(afterCache.finalLnOut, afterCache.headAttentionEntropy);
    const afterHostile = afterPred.heads[0].distribution[LearnedThreatClass.HOSTILE];

    // The model should have shifted toward the correct labels
    expect(afterHostile).toBeGreaterThan(initialHostile);
  });

  test("trained classifier distinguishes healthy from attack", () => {
    const model = new MiniTransformer(DEFAULT_CONFIG);
    model.initWeights("distinguish-test");
    const tokenizer = new ToolTokenizer();

    const classifier = new ThreatHeadClassifier();
    classifier.initWeights("distinguish-test");

    // Build lots of labeled examples with distinct patterns
    const examples: ThreatLabeledExample[] = [];
    for (let i = 0; i < 30; i++) {
      // Healthy
      examples.push({
        sequence: ["read_file", "grep", "write_file", "read_file"],
        intentVec: null,
        headLabels: [LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED],
      });
      // Attack
      examples.push({
        sequence: ["read_file", "web_fetch", "bash", "exec"],
        intentVec: null,
        headLabels: [LearnedThreatClass.HOSTILE, LearnedThreatClass.ALIGNED, LearnedThreatClass.ALIGNED],
      });
    }

    // Train directly
    const lr = 0.01;
    for (let epoch = 0; epoch < 20; epoch++) {
      for (const ex of examples) {
        for (const t of ex.sequence) tokenizer.addTool(t);
        const ids = tokenizer.encodeSequence(ex.sequence);
        const cache = model.forwardFull(ids, null);
        for (let h = 0; h < 3; h++) {
          const hCache = classifier.forwardWithCache(h, cache.finalLnOut, cache.headAttentionEntropy);
          const grad = classifier.backwardHead(h, hCache, ex.headLabels[h]);
          const head = classifier.weights.heads[h];
          for (let j = 0; j < grad.w1.length; j++) head.w1[j] -= lr * grad.w1[j];
          for (let j = 0; j < grad.b1.length; j++) head.b1[j] -= lr * grad.b1[j];
          for (let j = 0; j < grad.w2.length; j++) head.w2[j] -= lr * grad.w2[j];
          for (let j = 0; j < grad.b2.length; j++) head.b2[j] -= lr * grad.b2[j];
        }
      }
    }

    // Test: healthy sequence should have high ALIGNED probability
    const healthyIds = tokenizer.encodeSequence(["read_file", "grep", "write_file", "read_file"]);
    const healthyCache = model.forwardFull(healthyIds, null);
    const healthyPred = classifier.forward(healthyCache.finalLnOut, healthyCache.headAttentionEntropy);
    expect(healthyPred.heads[0].distribution[LearnedThreatClass.ALIGNED]).toBeGreaterThan(0.4);

    // Test: attack sequence should have higher HOSTILE probability
    const attackIds = tokenizer.encodeSequence(["read_file", "web_fetch", "bash", "exec"]);
    const attackCache = model.forwardFull(attackIds, null);
    const attackPred = classifier.forward(attackCache.finalLnOut, attackCache.headAttentionEntropy);
    expect(attackPred.heads[0].distribution[LearnedThreatClass.HOSTILE]).toBeGreaterThan(
      healthyPred.heads[0].distribution[LearnedThreatClass.HOSTILE],
    );
  });
});

// ─── ForwardCache headAttentionEntropy ───

describe("ForwardCache headAttentionEntropy", () => {
  test("forwardFull cache includes headAttentionEntropy", () => {
    const model = new MiniTransformer(DEFAULT_CONFIG);
    model.initWeights("cache-test");
    const tokenizer = new ToolTokenizer();
    const ids = tokenizer.encodeSequence(["read_file", "grep"]);
    const cache = model.forwardFull(ids, null);

    expect(cache.headAttentionEntropy).toBeDefined();
    expect(cache.headAttentionEntropy.length).toBe(
      DEFAULT_CONFIG.numHeads * DEFAULT_CONFIG.numLayers,
    );

    // All values should be non-negative (entropy is non-negative)
    for (let i = 0; i < cache.headAttentionEntropy.length; i++) {
      expect(cache.headAttentionEntropy[i]).toBeGreaterThanOrEqual(0);
    }
  });
});
