/**
 * Mini transformer tests — linalg, tokenizer, model, training, scoring.
 */

import { describe, test, expect, beforeEach, afterAll } from "vitest";
import { rmSync, readdirSync } from "node:fs";
import {
  matmul, matmulTransB, matmulTransA, addBias,
  softmax, softmaxRows, layerNorm, gelu, geluBackward,
  layerNormBackward, crossEntropyLoss, crossEntropySoftmaxBackward,
  add,
} from "../src/transformer/linalg.js";
import { ToolTokenizer, PAD, UNK, BOS, EOS } from "../src/transformer/tokenizer.js";
import { MiniTransformer, DEFAULT_CONFIG, flattenWeightsList } from "../src/transformer/model.js";
import { TransformerTrainer } from "../src/transformer/trainer.js";
import { TransformerScorer } from "../src/transformer/scorer.js";

// ─── Linear Algebra ───

describe("linalg", () => {
  test("matmul 2×3 × 3×2", () => {
    const A = new Float64Array([1, 2, 3, 4, 5, 6]);     // 2×3
    const B = new Float64Array([7, 8, 9, 10, 11, 12]);   // 3×2
    const C = matmul(A, B, 2, 3, 2);
    // [1*7+2*9+3*11, 1*8+2*10+3*12] = [58, 64]
    // [4*7+5*9+6*11, 4*8+5*10+6*12] = [139, 154]
    expect(C[0]).toBeCloseTo(58);
    expect(C[1]).toBeCloseTo(64);
    expect(C[2]).toBeCloseTo(139);
    expect(C[3]).toBeCloseTo(154);
  });

  test("matmulTransB computes A × B^T", () => {
    const A = new Float64Array([1, 2, 3, 4]);   // 2×2
    const B = new Float64Array([5, 6, 7, 8]);   // 2×2 (treated as transposed)
    const C = matmulTransB(A, B, 2, 2, 2);
    // A × B^T = [1*5+2*6, 1*7+2*8; 3*5+4*6, 3*7+4*8] = [17, 23, 39, 53]
    expect(C[0]).toBeCloseTo(17);
    expect(C[1]).toBeCloseTo(23);
    expect(C[2]).toBeCloseTo(39);
    expect(C[3]).toBeCloseTo(53);
  });

  test("softmax sums to 1", () => {
    const logits = new Float64Array([1, 2, 3, 4, 5]);
    const probs = softmax(logits, 5);
    const sum = probs.reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(1, 10);
    // Should be monotonically increasing
    for (let i = 1; i < 5; i++) {
      expect(probs[i]).toBeGreaterThan(probs[i - 1]);
    }
  });

  test("softmax is numerically stable with large values", () => {
    const logits = new Float64Array([1000, 1001, 1002]);
    const probs = softmax(logits, 3);
    const sum = probs.reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(1, 10);
    expect(probs[2]).toBeGreaterThan(probs[1]);
  });

  test("layerNorm produces zero mean unit variance", () => {
    const x = new Float64Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const gamma = new Float64Array(8).fill(1);
    const beta = new Float64Array(8).fill(0);
    const { out } = layerNorm(x, gamma, beta, 8);
    const mean = out.reduce((a, b) => a + b, 0) / 8;
    expect(mean).toBeCloseTo(0, 5);
    const variance = out.reduce((a, b) => a + b * b, 0) / 8;
    expect(variance).toBeCloseTo(1, 3);
  });

  test("gelu approximation", () => {
    const x = new Float64Array([0, 1, -1, 2, -2]);
    const y = gelu(x);
    expect(y[0]).toBeCloseTo(0, 5);       // GELU(0) = 0
    expect(y[1]).toBeCloseTo(0.8413, 2);  // GELU(1) ≈ 0.841
    expect(y[2]).toBeCloseTo(-0.1587, 2); // GELU(-1) ≈ -0.159
  });

  test("crossEntropyLoss correct", () => {
    const probs = new Float64Array([0.7, 0.2, 0.1]);
    expect(crossEntropyLoss(probs, 0)).toBeCloseTo(-Math.log(0.7));
    expect(crossEntropyLoss(probs, 2)).toBeCloseTo(-Math.log(0.1));
  });

  test("crossEntropySoftmaxBackward gradient", () => {
    const probs = new Float64Array([0.7, 0.2, 0.1]);
    const grad = crossEntropySoftmaxBackward(probs, 0, 3);
    expect(grad[0]).toBeCloseTo(-0.3); // 0.7 - 1.0
    expect(grad[1]).toBeCloseTo(0.2);  // 0.2 - 0.0
    expect(grad[2]).toBeCloseTo(0.1);  // 0.1 - 0.0
  });
});

// ─── Tokenizer ───

describe("ToolTokenizer", () => {
  test("encodes known tools", () => {
    const tok = new ToolTokenizer();
    const id = tok.encode("read");
    expect(id).toBeGreaterThanOrEqual(4); // After special tokens
    expect(tok.decode(id)).toBe("read");
  });

  test("unknown tool returns UNK", () => {
    const tok = new ToolTokenizer();
    expect(tok.encode("nonexistent_tool_xyz")).toBe(UNK);
  });

  test("encodeSequence prepends BOS", () => {
    const tok = new ToolTokenizer();
    const ids = tok.encodeSequence(["read", "edit", "exec"]);
    expect(ids[0]).toBe(BOS);
    expect(ids.length).toBe(4);
  });

  test("addTool grows vocabulary", () => {
    const tok = new ToolTokenizer();
    const sizeBefore = tok.vocabSize();
    tok.addTool("brand_new_tool");
    expect(tok.vocabSize()).toBe(sizeBefore + 1);
    expect(tok.encode("brand_new_tool")).toBe(sizeBefore);
  });

  test("serialization roundtrip", () => {
    const tok = new ToolTokenizer();
    tok.addTool("custom_tool");
    const json = tok.toJSON();
    const tok2 = ToolTokenizer.fromJSON(json);
    expect(tok2.encode("read")).toBe(tok.encode("read"));
    expect(tok2.encode("custom_tool")).toBe(tok.encode("custom_tool"));
    expect(tok2.vocabSize()).toBe(tok.vocabSize());
  });

  test("case insensitive", () => {
    const tok = new ToolTokenizer();
    expect(tok.encode("Read")).toBe(tok.encode("read"));
    expect(tok.encode("EXEC")).toBe(tok.encode("exec"));
  });
});

// ─── Model ───

describe("MiniTransformer", () => {
  let model: MiniTransformer;

  beforeEach(() => {
    model = new MiniTransformer({
      ...DEFAULT_CONFIG,
      vocabSize: 32,
      hiddenDim: 16,
      numHeads: 2,
      numLayers: 1,
      ffnDim: 32,
      maxSeqLen: 32,
    });
    model.initWeights("test-seed");
  });

  test("forward returns correct shape", () => {
    const logits = model.forward([2, 4, 5, 6]); // BOS + 3 tools
    expect(logits.length).toBe(32); // vocabSize
  });

  test("predict returns valid probability distribution", () => {
    const probs = model.predict([2, 4, 5]);
    const sum = probs.reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(1, 5);
    for (let i = 0; i < probs.length; i++) {
      expect(probs[i]).toBeGreaterThanOrEqual(0);
    }
  });

  test("deterministic output for same input", () => {
    const probs1 = model.predict([2, 4, 5, 6]);
    const probs2 = model.predict([2, 4, 5, 6]);
    for (let i = 0; i < probs1.length; i++) {
      expect(probs1[i]).toBeCloseTo(probs2[i], 10);
    }
  });

  test("different inputs give different outputs", () => {
    const probs1 = model.predict([2, 4, 5, 6]);
    const probs2 = model.predict([2, 7, 8, 9]);
    let same = true;
    for (let i = 0; i < probs1.length; i++) {
      if (Math.abs(probs1[i] - probs2[i]) > 1e-6) { same = false; break; }
    }
    expect(same).toBe(false);
  });

  test("param count is reasonable", () => {
    const count = model.paramCount();
    expect(count).toBeGreaterThan(1000);
    expect(count).toBeLessThan(50000);
  });

  test("weight serialization roundtrip", () => {
    const probs1 = model.predict([2, 4, 5]);
    const buf = model.serializeWeights();
    const model2 = new MiniTransformer(model.config);
    model2.deserializeWeights(buf);
    const probs2 = model2.predict([2, 4, 5]);
    for (let i = 0; i < probs1.length; i++) {
      expect(probs2[i]).toBeCloseTo(probs1[i], 10);
    }
  });

  test("backward returns gradients with correct shapes", () => {
    const cache = model.forwardFull([2, 4, 5, 6]);
    const grad = model.backward(cache, 7);
    // Check gradient shapes match weight shapes
    const wList = flattenWeightsList(model.weights);
    const gList = flattenWeightsList(grad);
    expect(wList.length).toBe(gList.length);
    for (let i = 0; i < wList.length; i++) {
      expect(gList[i].length).toBe(wList[i].length);
    }
  });

  test("gradient check — finite difference vs backprop", () => {
    const smallModel = new MiniTransformer({
      ...DEFAULT_CONFIG,
      vocabSize: 8,
      hiddenDim: 4,
      numHeads: 1,
      numLayers: 1,
      ffnDim: 8,
      maxSeqLen: 8,
    });
    smallModel.initWeights("grad-check");

    const input = [2, 4, 5];
    const target = 6;
    const eps = 1e-5;

    // Get analytical gradient
    const cache = smallModel.forwardFull(input);
    const analyticalGrad = smallModel.backward(cache, target);

    // Check a few parameters from the output projection
    const wList = flattenWeightsList(smallModel.weights);
    const gList = flattenWeightsList(analyticalGrad);

    // Test output projection weights (last-2 tensor)
    const tensorIdx = wList.length - 2; // outProj
    const w = wList[tensorIdx];
    const g = gList[tensorIdx];

    let maxRelError = 0;
    const checkCount = Math.min(10, w.length);
    for (let i = 0; i < checkCount; i++) {
      const orig = w[i];

      // f(w + eps)
      w[i] = orig + eps;
      const cache1 = smallModel.forwardFull(input);
      const loss1 = crossEntropyLoss(cache1.probs, target);

      // f(w - eps)
      w[i] = orig - eps;
      const cache2 = smallModel.forwardFull(input);
      const loss2 = crossEntropyLoss(cache2.probs, target);

      w[i] = orig; // restore

      const numGrad = (loss1 - loss2) / (2 * eps);
      const relError = Math.abs(numGrad - g[i]) / (Math.abs(numGrad) + Math.abs(g[i]) + 1e-8);
      maxRelError = Math.max(maxRelError, relError);
    }

    expect(maxRelError).toBeLessThan(0.01); // 1% relative error tolerance
  });
});

// ─── Training ───

describe("TransformerTrainer", () => {
  test("overfit on a single repeated sequence", async () => {
    const tok = new ToolTokenizer();
    tok.addTool("a"); tok.addTool("b"); tok.addTool("c");
    const model = new MiniTransformer({
      ...DEFAULT_CONFIG,
      vocabSize: tok.vocabSize(), // Must match tokenizer
      hiddenDim: 16,
      numHeads: 2,
      numLayers: 1,
      ffnDim: 32,
      maxSeqLen: 32,
    });
    model.initWeights("overfit-test");

    const trainer = new TransformerTrainer(model, tok, {
      learningRate: 0.003,
      minLearningRate: 0.0005,
      batchSize: 4,
      maxEpochs: 50,
      warmupSteps: 10,
      maxSequences: 100,
      gradClipNorm: 0.5,
    });

    // Train on 20 copies of the same sequence
    const sequences = Array(20).fill(["a", "b", "c", "a", "b", "c"]);
    const result = await trainer.trainOnSequences(sequences);

    expect(result.finalLoss).toBeLessThan(1.0);
    expect(result.epochs).toBe(50);
    expect(result.sequencesUsed).toBe(20);

    // After training, model should predict the pattern
    const probs = model.predict(tok.encodeSequence(["a", "b"]));
    const cId = tok.encode("c");
    // "c" should have highest probability after "a, b"
    let maxProb = 0;
    let maxId = 0;
    for (let i = 0; i < probs.length; i++) {
      if (probs[i] > maxProb) { maxProb = probs[i]; maxId = i; }
    }
    expect(maxId).toBe(cId);
  });

  test("loss decreases over training", async () => {
    const tok = new ToolTokenizer();
    tok.addTool("read"); tok.addTool("edit"); tok.addTool("exec");
    const model = new MiniTransformer({
      ...DEFAULT_CONFIG,
      vocabSize: tok.vocabSize(),
      hiddenDim: 16,
      numHeads: 2,
      numLayers: 1,
      ffnDim: 32,
      maxSeqLen: 32,
    });
    model.initWeights("loss-test");

    const sequences = Array(30).fill(["read", "edit", "exec", "read", "edit"]);

    // Train 5 epochs
    const trainer1 = new TransformerTrainer(model, tok, {
      learningRate: 0.01, minLearningRate: 0.001,
      batchSize: 4, maxEpochs: 5, warmupSteps: 5,
      maxSequences: 100, gradClipNorm: 1.0,
    });
    const result1 = await trainer1.trainOnSequences(sequences);

    // Train 5 more
    const trainer2 = new TransformerTrainer(model, tok, {
      learningRate: 0.005, minLearningRate: 0.001,
      batchSize: 4, maxEpochs: 5, warmupSteps: 0,
      maxSequences: 100, gradClipNorm: 1.0,
    });
    const result2 = await trainer2.trainOnSequences(sequences);

    expect(result2.finalLoss).toBeLessThan(result1.finalLoss);
  });
});

// ─── Scorer ───

describe("TransformerScorer", () => {
  afterAll(() => {
    try {
      for (const d of readdirSync("/tmp").filter(f => f.startsWith("shroud-test-transformer-") || (f.startsWith("shroud-test-") && !f.includes("traces")))) {
        try { rmSync("/tmp/" + d, { recursive: true, force: true }); } catch {}
      }
    } catch {}
  });

  test("cold start returns neutral scores", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-transformer-" + Date.now());
    const prediction = scorer.scoreToolCall(["read", "edit"], "exec");
    expect(prediction.surprise).toBe(0);
    expect(prediction.sessionAnomalyScore).toBe(0);
  });

  test("trained model scores known patterns low", { timeout: 15000 }, async () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-transformer-" + Date.now(), {
      anomalyThreshold: 0.85,
      windowSize: 10,
      minSequenceLength: 2,
      minSessionsToTrain: 5,
      trainIntervalSessions: 50,
    });

    // Manually train the scorer's model
    const model = (scorer as any)._model as MiniTransformer;
    const tok = (scorer as any)._tokenizer as ToolTokenizer;
    tok.addTool("read"); tok.addTool("edit"); tok.addTool("exec");
    model.initWeights("scorer-test");

    const trainer = new TransformerTrainer(model, tok, {
      learningRate: 0.01, minLearningRate: 0.001,
      batchSize: 4, maxEpochs: 30, warmupSteps: 5,
      maxSequences: 100, gradClipNorm: 1.0,
    });
    await trainer.trainOnSequences(Array(30).fill(["read", "edit", "exec", "read", "edit"]));
    (scorer as any)._modelLoaded = true;

    // Known pattern should have low surprise
    const pred = scorer.scoreToolCall(["read", "edit"], "exec");
    expect(pred.surprise).toBeLessThan(0.7);
  });

  test("checkAnomaly returns null for low surprise", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-" + Date.now());
    const prediction = { topK: [], surprise: 0.3, perplexity: 1.5, sessionAnomalyScore: 0.3 };
    expect(scorer.checkAnomaly(prediction, "read")).toBeNull();
  });

  test("checkAnomaly returns event for high surprise", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-" + Date.now());
    const prediction = { topK: [{ tool: "edit", prob: 0.8 }], surprise: 0.92, perplexity: 12, sessionAnomalyScore: 0.9 };
    const event = scorer.checkAnomaly(prediction, "web_fetch", "TestAgent");
    expect(event).not.toBeNull();
    expect(event!.threatClass).toBe("tool_sequence_anomaly");
    expect(event!.severity).toBe("medium");
    expect(event!.agentLabel).toBe("TestAgent");
  });

  test("getStats returns valid structure", () => {
    const scorer = new TransformerScorer("/tmp/shroud-test-" + Date.now());
    const stats = scorer.getStats();
    expect(stats.enabled).toBe(true);
    expect(stats.modelLoaded).toBe(false);
    expect(stats.totalParams).toBeGreaterThan(0);
  });
});
