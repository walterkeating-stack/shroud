#!/usr/bin/env npx tsx
/**
 * Pre-train the mini transformer from testbed data.
 *
 * Usage: npx tsx scripts/pretrain-transformer.ts [--profile-dir <dir>]
 *
 * Outputs weights to ~/.shroud/profiles/ (or specified dir).
 * Validates separation between healthy and attack embeddings.
 */

import { seedPretrain } from "../src/transformer/seed-pretrain.js";
import { HEALTHY_SEQUENCES, ATTACK_TRACES, generateSyntheticIntent } from "../src/transformer/pretrain-testbed.js";
import { l2Distance } from "../src/transformer/linalg.js";
import { BOS } from "../src/transformer/tokenizer.js";
import { homedir } from "node:os";
import { join } from "node:path";

const profileDir = process.argv.includes("--profile-dir")
  ? process.argv[process.argv.indexOf("--profile-dir") + 1]
  : join(homedir(), ".shroud", "profiles");

console.log(`Pre-training transformer → ${profileDir}`);
console.log(`  Healthy sequences: ${HEALTHY_SEQUENCES.length}`);
console.log(`  Attack traces:     ${ATTACK_TRACES.length}`);
console.log();

const start = Date.now();
const { trainResult, model, tokenizer, threatClassifier } = await seedPretrain(profileDir);
const elapsed = Date.now() - start;

console.log(`Training complete in ${elapsed}ms:`);
console.log(`  Final loss:       ${trainResult.finalLoss.toFixed(4)}`);
console.log(`  Contrastive loss: ${trainResult.contrastiveLoss.toFixed(4)}`);
console.log(`  Threat head loss: ${trainResult.threatHeadLoss.toFixed(4)}`);
console.log(`  Epochs:           ${trainResult.epochs}`);
console.log(`  Sequences used:   ${trainResult.sequencesUsed}`);
console.log();

// ── Validate embedding separation ──
console.log("Validating embedding separation...");

const healthyEmbeddings: Float64Array[] = [];
const attackEmbeddings: Float64Array[] = [];

for (let i = 0; i < HEALTHY_SEQUENCES.length; i++) {
  const ids = [BOS, ...tokenizer.encodeSequence(HEALTHY_SEQUENCES[i])];
  const intent = generateSyntheticIntent(`healthy-${i}-${HEALTHY_SEQUENCES[i].join(",")}`);
  healthyEmbeddings.push(model.getEmbedding(ids, intent));
}

for (const trace of ATTACK_TRACES) {
  const fullSeq = [...trace.legitimatePrefix, ...trace.hijackedSuffix];
  const ids = [BOS, ...tokenizer.encodeSequence(fullSeq)];
  attackEmbeddings.push(model.getEmbedding(ids, null));
}

// Compute intra-healthy distances
let intraSum = 0;
let intraCount = 0;
for (let i = 0; i < healthyEmbeddings.length; i++) {
  for (let j = i + 1; j < healthyEmbeddings.length; j++) {
    intraSum += l2Distance(healthyEmbeddings[i], healthyEmbeddings[j], model.config.hiddenDim);
    intraCount++;
  }
}
const meanIntra = intraSum / intraCount;

// Compute cross-cluster distances
let crossSum = 0;
let crossCount = 0;
for (const h of healthyEmbeddings) {
  for (const a of attackEmbeddings) {
    crossSum += l2Distance(h, a, model.config.hiddenDim);
    crossCount++;
  }
}
const meanCross = crossSum / crossCount;

const ratio = meanCross / meanIntra;
console.log(`  Mean intra-healthy L2:  ${meanIntra.toFixed(4)}`);
console.log(`  Mean cross-cluster L2:  ${meanCross.toFixed(4)}`);
console.log(`  Separation ratio:       ${ratio.toFixed(2)}x`);

// ── Validate threat head accuracy ──
console.log("\nValidating threat head classification...");

let healthyCorrect = 0;
for (let i = 0; i < HEALTHY_SEQUENCES.length; i++) {
  const ids = [BOS, ...tokenizer.encodeSequence(HEALTHY_SEQUENCES[i])];
  const intent = generateSyntheticIntent(`healthy-${i}-${HEALTHY_SEQUENCES[i].join(",")}`);
  const emb = model.getEmbedding(ids, intent);
  const entropy = new Float64Array(8);
  const pred = threatClassifier.forward(emb, entropy);
  if (pred.threatScore < 0.5) healthyCorrect++;
}

let attackHostile = 0;
for (const trace of ATTACK_TRACES) {
  const fullSeq = [...trace.legitimatePrefix, ...trace.hijackedSuffix];
  const ids = [BOS, ...tokenizer.encodeSequence(fullSeq)];
  const emb = model.getEmbedding(ids, null);
  const entropy = new Float64Array(8);
  const pred = threatClassifier.forward(emb, entropy);
  if (pred.threatScore >= 0.5) attackHostile++;
}

const healthyAcc = (healthyCorrect / HEALTHY_SEQUENCES.length * 100).toFixed(0);
const attackAcc = (attackHostile / ATTACK_TRACES.length * 100).toFixed(0);

console.log(`  Healthy → low threat:   ${healthyCorrect}/${HEALTHY_SEQUENCES.length} (${healthyAcc}%)`);
console.log(`  Attack → high threat:   ${attackHostile}/${ATTACK_TRACES.length} (${attackAcc}%)`);

// ── Summary ──
console.log("\n" + "═".repeat(50));
const pass = trainResult.finalLoss < 0.5;
console.log(pass ? "PASS: Pre-training successful" : "WARN: Metrics below threshold");
console.log("═".repeat(50));

process.exit(pass ? 0 : 1);
