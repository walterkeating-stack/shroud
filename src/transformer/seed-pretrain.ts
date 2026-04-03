/**
 * Seed pre-training for the mini transformer.
 *
 * Bootstraps all 4 tiers from testbed data so the model has a decision
 * boundary from the first session. Called automatically on cold start
 * (no weights on disk) by TransformerScorer.create().
 *
 * Takes < 1 second on CPU.
 */

import { MiniTransformer, DEFAULT_CONFIG } from "./model.js";
import { ToolTokenizer } from "./tokenizer.js";
import { TransformerTrainer, DEFAULT_TRAINER_CONFIG, type TrainResult } from "./trainer.js";
import { AttackTraceStore } from "./contrastive.js";
import { ThreatHeadClassifier } from "./threat-heads.js";
import {
  HEALTHY_SEQUENCES,
  ATTACK_TRACES,
  generateTestbedIntents,
  generateTestbedLabels,
} from "./pretrain-testbed.js";
import { writeFileSync, mkdirSync } from "node:fs";

const PRETRAIN_SEED = "shroud-pretrain-v1";

export interface SeedPretrainResult {
  trainResult: TrainResult;
  model: MiniTransformer;
  tokenizer: ToolTokenizer;
  threatClassifier: ThreatHeadClassifier;
}

/**
 * Run seed pre-training and save weights to profileDir.
 * Returns the trained model and training metrics.
 */
export async function seedPretrain(profileDir: string): Promise<SeedPretrainResult> {
  // Ensure profile directory exists
  try { mkdirSync(profileDir, { recursive: true }); } catch {}

  // Initialize model with deterministic seed
  const model = new MiniTransformer(DEFAULT_CONFIG);
  model.initWeights(PRETRAIN_SEED);

  const tokenizer = new ToolTokenizer();

  // Initialize threat heads with deterministic seed
  const threatClassifier = new ThreatHeadClassifier();
  threatClassifier.initWeights(PRETRAIN_SEED);

  // Build training sequences: healthy + attack (full sequences)
  const allSequences: string[][] = [
    ...HEALTHY_SEQUENCES,
    ...ATTACK_TRACES.map(t => [...t.legitimatePrefix, ...t.hijackedSuffix]),
  ];

  // Generate intent vectors and threat labels
  const intentVecs = generateTestbedIntents(HEALTHY_SEQUENCES, ATTACK_TRACES);
  const threatLabels = generateTestbedLabels(HEALTHY_SEQUENCES, ATTACK_TRACES);

  // Seed the attack trace store
  const traceStore = new AttackTraceStore(profileDir);
  for (const trace of ATTACK_TRACES) {
    traceStore.add({ ...trace, timestamp: Date.now() });
  }
  traceStore.save();

  // Train with deterministic seed
  const trainer = new TransformerTrainer(model, tokenizer, {
    ...DEFAULT_TRAINER_CONFIG,
    rngSeed: PRETRAIN_SEED,
    maxEpochs: 20,       // Enough for small testbed (35 sequences), <2s on CPU
    maxSequences: 500,
  });

  const trainResult = await trainer.trainOnSequences(
    allSequences,
    intentVecs,
    ATTACK_TRACES,
    threatClassifier,
    threatLabels,
  );

  // Save weights
  const weightsBuf = model.serializeWeights();
  writeFileSync(`${profileDir}/transformer-weights.bin`, weightsBuf);

  // Save config (tokenizer vocab + model config + training metadata)
  const configJson = {
    modelConfig: model.config,
    tokenizer: tokenizer.toJSON(),
    lastTrainedAt: Date.now(),
    trainingSessions: allSequences.length,
    lastLoss: trainResult.finalLoss,
    contrastiveLoss: trainResult.contrastiveLoss,
    threatHeadLoss: trainResult.threatHeadLoss,
    seed: PRETRAIN_SEED,
    pretrainVersion: 1,
  };
  writeFileSync(`${profileDir}/transformer-config.json`, JSON.stringify(configJson, null, 2));

  // Save threat head weights
  const threatBuf = threatClassifier.serialize();
  writeFileSync(`${profileDir}/threat-heads-weights.bin`, Buffer.from(threatBuf.buffer));

  return { trainResult, model, tokenizer, threatClassifier };
}
