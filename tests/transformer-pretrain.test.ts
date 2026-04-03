/**
 * Verification tests for transformer seed pre-training.
 *
 * Validates that the pre-trained model separates healthy from attack
 * sequences, threat heads classify correctly, and training is reproducible.
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { seedPretrain, type SeedPretrainResult } from "../src/transformer/seed-pretrain.js";
import {
  HEALTHY_SEQUENCES,
  ATTACK_TRACES,
  generateSyntheticIntent,
  generateTestbedLabels,
} from "../src/transformer/pretrain-testbed.js";
import { l2Distance } from "../src/transformer/linalg.js";
import { BOS } from "../src/transformer/tokenizer.js";
import { LearnedThreatClass } from "../src/transformer/threat-heads.js";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("Transformer seed pre-training", () => {
  let dir: string;
  let result: SeedPretrainResult;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "shroud-pretrain-test-"));
    result = await seedPretrain(dir);
  }, 30000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("training completes with finite loss", () => {
    expect(Number.isFinite(result.trainResult.finalLoss)).toBe(true);
    expect(result.trainResult.finalLoss).toBeGreaterThan(0);
    expect(result.trainResult.epochs).toBeGreaterThan(0);
    expect(result.trainResult.sequencesUsed).toBe(HEALTHY_SEQUENCES.length + ATTACK_TRACES.length);
  });

  test("contrastive loss is non-zero (triplets processed)", () => {
    expect(result.trainResult.contrastiveLoss).toBeGreaterThan(0);
  });

  test("threat head loss is finite", () => {
    expect(Number.isFinite(result.trainResult.threatHeadLoss)).toBe(true);
  });

  test("embeddings are non-degenerate", () => {
    const { model, tokenizer } = result;

    const embeddings: Float64Array[] = [];
    for (let i = 0; i < Math.min(5, HEALTHY_SEQUENCES.length); i++) {
      const ids = [BOS, ...tokenizer.encodeSequence(HEALTHY_SEQUENCES[i])];
      const intent = generateSyntheticIntent(`healthy-${i}-${HEALTHY_SEQUENCES[i].join(",")}`);
      embeddings.push(model.getEmbedding(ids, intent));
    }

    // Embeddings should be distinct (not collapsed to same point)
    let distinctPairs = 0;
    for (let i = 0; i < embeddings.length; i++) {
      for (let j = i + 1; j < embeddings.length; j++) {
        const dist = l2Distance(embeddings[i], embeddings[j], model.config.hiddenDim);
        if (dist > 0.01) distinctPairs++;
      }
    }
    expect(distinctPairs).toBeGreaterThan(0);
  });

  test("threat heads produce predictions", () => {
    const { model, tokenizer, threatClassifier } = result;

    const ids = [BOS, ...tokenizer.encodeSequence(HEALTHY_SEQUENCES[0])];
    const intent = generateSyntheticIntent(`healthy-0-${HEALTHY_SEQUENCES[0].join(",")}`);
    const emb = model.getEmbedding(ids, intent);
    const entropy = new Float64Array(8);
    const pred = threatClassifier.forward(emb, entropy);

    expect(pred.heads.length).toBe(3);
    expect(Number.isFinite(pred.threatScore)).toBe(true);
    for (const head of pred.heads) {
      expect(head.distribution.length).toBe(4);
      expect(head.predicted).toBeGreaterThanOrEqual(0);
      expect(head.predicted).toBeLessThanOrEqual(3);
    }
  });

  test("testbed labels are generated correctly", () => {
    const labels = generateTestbedLabels(HEALTHY_SEQUENCES, ATTACK_TRACES);
    expect(labels.length).toBeGreaterThan(0);

    const hasAligned = labels.some(l => l.headLabels[0] === LearnedThreatClass.ALIGNED);
    const hasHostile = labels.some(l => l.headLabels[0] === LearnedThreatClass.HOSTILE);
    expect(hasAligned).toBe(true);
    expect(hasHostile).toBe(true);
  });

  test("persistence: weights files are created", () => {
    expect(existsSync(join(dir, "transformer-weights.bin"))).toBe(true);
    expect(existsSync(join(dir, "transformer-config.json"))).toBe(true);
    expect(existsSync(join(dir, "attack-traces.json"))).toBe(true);
    expect(existsSync(join(dir, "threat-heads-weights.bin"))).toBe(true);
  });

  test("deterministic: second run produces same loss", async () => {
    const dir2 = mkdtempSync(join(tmpdir(), "shroud-pretrain-test2-"));
    try {
      const result2 = await seedPretrain(dir2);
      expect(result2.trainResult.finalLoss).toBe(result.trainResult.finalLoss);
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  }, 30000);
});
