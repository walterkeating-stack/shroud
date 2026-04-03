/**
 * Self-supervised trainer for the mini transformer.
 *
 * Training objective: next-tool prediction.
 * Given a sequence [BOS, tool_0, ..., tool_i], predict tool_{i+1}.
 *
 * Uses Adam optimizer with cosine learning rate decay and linear warmup.
 * Trains in-process — 113K params on 500 sequences for 10 epochs < 1 second.
 */

import { type MiniTransformer, type TransformerWeights, flattenWeightsList } from "./model.js";
import { type ToolTokenizer, BOS } from "./tokenizer.js";
import { crossEntropyLoss, fnv1a, xorshift32 } from "./linalg.js";
import { ContrastiveTrainer, DEFAULT_CONTRASTIVE_CONFIG, type AttackTrace } from "./contrastive.js";
import { ThreatHeadClassifier, type ThreatLabeledExample, LEARNED_THREAT_CLASS_COUNT } from "./threat-heads.js";

// ─── Types ───

export interface TrainerConfig {
  learningRate: number;          // 0.001
  minLearningRate: number;       // 0.0001
  batchSize: number;             // 8
  maxEpochs: number;             // 10
  warmupSteps: number;           // 50
  maxSequences: number;          // 500 (sample if store is larger)
  gradClipNorm: number;          // 1.0
  rngSeed?: string;              // When set, shuffle uses seeded PRNG for reproducibility
}

export interface TrainResult {
  finalLoss: number;
  contrastiveLoss: number;
  threatHeadLoss: number;
  epochs: number;
  totalSteps: number;
  durationMs: number;
  sequencesUsed: number;
}

export const DEFAULT_TRAINER_CONFIG: TrainerConfig = {
  learningRate: 0.001,
  minLearningRate: 0.0001,
  batchSize: 8,
  maxEpochs: 10,
  warmupSteps: 50,
  maxSequences: 500,
  gradClipNorm: 1.0,
};

// ─── Adam optimizer state ───

interface AdamState {
  m: Float64Array[];   // first moment (mean of gradients)
  v: Float64Array[];   // second moment (mean of squared gradients)
  t: number;           // step counter
}

function createAdamState(weights: TransformerWeights): AdamState {
  const wList = flattenWeightsList(weights);
  return {
    m: wList.map(w => new Float64Array(w.length)),
    v: wList.map(w => new Float64Array(w.length)),
    t: 0,
  };
}

// ─── Trainer ───

export class TransformerTrainer {
  private _model: MiniTransformer;
  private _tokenizer: ToolTokenizer;
  private _config: TrainerConfig;
  private _adamState: AdamState | null = null;
  private _rngState: { s: number } | null = null;

  constructor(
    model: MiniTransformer,
    tokenizer: ToolTokenizer,
    config: TrainerConfig = DEFAULT_TRAINER_CONFIG,
  ) {
    this._model = model;
    this._tokenizer = tokenizer;
    this._config = config;
    if (config.rngSeed) {
      this._rngState = { s: fnv1a(config.rngSeed) || 1 };
    }
  }

  /**
   * Train on a list of tool-call sequences (from VectorStore workflows).
   * Each sequence is a string[] of tool names.
   * Optional intentVecs: parallel array of 256-dim TF-IDF embeddings of the user message
   * that initiated each session (enables intent-conditioned prediction).
   * Optional attackTraces: if provided and non-empty, contrastive mini-batches run
   * after the cross-entropy loop (lambda=0.3 weighting).
   */
  async trainOnSequences(
    sequences: string[][],
    intentVecs?: Array<Float64Array | null>,
    attackTraces?: AttackTrace[],
    threatClassifier?: ThreatHeadClassifier,
    threatLabels?: ThreatLabeledExample[],
  ): Promise<TrainResult> {
    const start = Date.now();
    const cfg = this._config;

    // Filter sequences with at least 2 tools (need input + target)
    let data = sequences.filter(s => s.length >= 2);
    if (data.length === 0) return { finalLoss: 0, contrastiveLoss: 0, threatHeadLoss: 0, epochs: 0, totalSteps: 0, durationMs: 0, sequencesUsed: 0 };

    // Sample if too many
    if (data.length > cfg.maxSequences) {
      data = this._sampleSequences(data, cfg.maxSequences);
    }

    // Ensure all tools are in the tokenizer
    for (const seq of data) {
      for (const tool of seq) {
        this._tokenizer.addTool(tool);
      }
    }

    // Prepare training examples: (prefix, target, intentVec) triples
    const examples: Array<{ input: number[]; target: number; intentVec: Float64Array | null }> = [];
    for (let s = 0; s < data.length; s++) {
      const seq = data[s];
      const encoded = this._tokenizer.encodeSequence(seq);
      const intent = intentVecs ? intentVecs[s] || null : null;
      // For each position i (starting from 1, since 0 is BOS), predict position i+1
      for (let i = 1; i < encoded.length - 1; i++) {
        examples.push({
          input: encoded.slice(0, i + 1),     // [BOS, tool_0, ..., tool_i]
          target: encoded[i + 1],             // tool_{i+1}
          intentVec: intent,
        });
      }
    }

    if (examples.length === 0) return { finalLoss: 0, contrastiveLoss: 0, threatHeadLoss: 0, epochs: 0, totalSteps: 0, durationMs: 0, sequencesUsed: data.length };

    // Initialize Adam state
    if (!this._adamState) {
      this._adamState = createAdamState(this._model.weights);
    }

    const totalSteps = Math.ceil(examples.length / cfg.batchSize) * cfg.maxEpochs;
    let step = 0;
    let lastLoss = 0;

    for (let epoch = 0; epoch < cfg.maxEpochs; epoch++) {
      // Yield to event loop between epochs so the gateway stays responsive
      if (epoch > 0) await new Promise<void>(r => setImmediate(r));

      // Shuffle examples
      this._shuffle(examples);

      let epochLoss = 0;
      let epochCount = 0;

      for (let b = 0; b < examples.length; b += cfg.batchSize) {
        // Yield every 8 batches to keep the event loop responsive
        if (b > 0 && (b / cfg.batchSize) % 8 === 0) await new Promise<void>(r => setImmediate(r));

        const batchEnd = Math.min(b + cfg.batchSize, examples.length);
        const batchSize = batchEnd - b;

        // Accumulate gradients across the batch
        const accumGrad = this._model["_allocateWeights"]();
        let batchLoss = 0;

        for (let i = b; i < batchEnd; i++) {
          const { input, target, intentVec } = examples[i];

          // Forward pass (with intent vector if available)
          const cache = this._model.forwardFull(input, intentVec);
          batchLoss += crossEntropyLoss(cache.probs, target);

          // Backward pass
          const grad = this._model.backward(cache, target);

          // Accumulate
          const accumList = flattenWeightsList(accumGrad);
          const gradList = flattenWeightsList(grad);
          for (let t = 0; t < accumList.length; t++) {
            const a = accumList[t];
            const g = gradList[t];
            for (let j = 0; j < a.length; j++) a[j] += g[j];
          }
        }

        // Average gradients
        const accumList = flattenWeightsList(accumGrad);
        for (const a of accumList) {
          for (let j = 0; j < a.length; j++) a[j] /= batchSize;
        }

        // Gradient clipping (by global norm)
        this._clipGradients(accumList, cfg.gradClipNorm);

        // Learning rate with warmup + cosine decay
        const lr = this._getLearningRate(step, totalSteps);

        // Adam update
        this._adamStep(accumList, lr);

        epochLoss += batchLoss;
        epochCount += batchSize;
        step++;
      }

      lastLoss = epochLoss / epochCount;
    }

    // ── Contrastive mini-batches (Tier 2) ──
    // After cross-entropy training, run triplet loss through the shared backbone
    // if attack traces are available. This separates healthy vs hijacked embeddings.
    let contrastiveLoss = 0;
    if (attackTraces && attackTraces.length > 0 && data.length >= 2) {
      const contrastiveTrainer = new ContrastiveTrainer(
        this._model,
        this._tokenizer,
        DEFAULT_CONTRASTIVE_CONFIG,
      );
      const cResult = await contrastiveTrainer.trainOnTraces(attackTraces, data, intentVecs);
      contrastiveLoss = cResult.loss;
    }

    // ── Threat head training (Tier 4) ──
    // After backbone training, train threat heads on labeled examples
    // (backbone is frozen — only threat head weights update).
    let threatHeadLoss = 0;
    if (threatClassifier && threatLabels && threatLabels.length > 0) {
      threatHeadLoss = await this._trainThreatHeads(threatClassifier, threatLabels);
    }

    return {
      finalLoss: lastLoss,
      contrastiveLoss,
      threatHeadLoss,
      epochs: cfg.maxEpochs,
      totalSteps: step,
      durationMs: Date.now() - start,
      sequencesUsed: data.length,
    };
  }

  /**
   * Train threat head classifier on labeled examples.
   * Backbone is frozen — only threat head MLP weights are updated.
   * Returns average loss across all examples and heads.
   */
  private async _trainThreatHeads(
    classifier: ThreatHeadClassifier,
    examples: ThreatLabeledExample[],
  ): Promise<number> {
    const lr = 0.005;
    const numEpochs = 5;
    let totalLoss = 0;
    let totalCount = 0;

    for (let epoch = 0; epoch < numEpochs; epoch++) {
      // Yield between epochs to keep the event loop responsive
      if (epoch > 0) await new Promise<void>(r => setImmediate(r));

      // Shuffle examples
      const shuffled = [...examples];
      this._shuffle(shuffled);

      let exampleIdx = 0;
      for (const example of shuffled) {
        // Yield every 10 examples to prevent event loop starvation
        if (exampleIdx > 0 && exampleIdx % 10 === 0) await new Promise<void>(r => setImmediate(r));
        exampleIdx++;
        if (example.sequence.length < 2) continue;

        // Ensure tools are in tokenizer
        for (const t of example.sequence) this._tokenizer.addTool(t);

        // Forward pass through backbone (frozen) to get embedding + entropy
        const tokenIds = this._tokenizer.encodeSequence(example.sequence);
        const cache = this._model.forwardFull(tokenIds, example.intentVec);

        const backboneEmb = cache.finalLnOut;
        const headEntropy = cache.headAttentionEntropy;

        // Train each head independently
        for (let h = 0; h < 3; h++) {
          const headCache = classifier.forwardWithCache(h, backboneEmb, headEntropy);
          const target = example.headLabels[h];

          // Cross-entropy loss
          const loss = -Math.log(Math.max(headCache.probs[target], 1e-12));
          totalLoss += loss;
          totalCount++;

          // Backward pass (get gradients for this head)
          const grad = classifier.backwardHead(h, headCache, target);

          // SGD update (simple, no Adam needed for ~1236 params)
          const head = classifier.weights.heads[h];
          for (let i = 0; i < grad.w1.length; i++) head.w1[i] -= lr * grad.w1[i];
          for (let i = 0; i < grad.b1.length; i++) head.b1[i] -= lr * grad.b1[i];
          for (let i = 0; i < grad.w2.length; i++) head.w2[i] -= lr * grad.w2[i];
          for (let i = 0; i < grad.b2.length; i++) head.b2[i] -= lr * grad.b2[i];

          // Update reliability based on whether prediction matches label
          const predicted = headCache.probs[target] > 0.5;
          classifier.updateReliability(h, predicted);
        }
      }
    }

    return totalCount > 0 ? totalLoss / totalCount : 0;
  }

  /** Get the current learning rate with warmup + cosine decay. */
  private _getLearningRate(step: number, totalSteps: number): number {
    const { learningRate, minLearningRate, warmupSteps } = this._config;
    if (step < warmupSteps) {
      return learningRate * (step + 1) / warmupSteps;
    }
    const progress = (step - warmupSteps) / Math.max(1, totalSteps - warmupSteps);
    return minLearningRate + 0.5 * (learningRate - minLearningRate) * (1 + Math.cos(Math.PI * progress));
  }

  /** Adam optimizer step. Mutates model weights in place. */
  private _adamStep(gradients: Float64Array[], lr: number): void {
    const adam = this._adamState!;
    adam.t++;
    const beta1 = 0.9;
    const beta2 = 0.999;
    const eps = 1e-8;
    const bc1 = 1 - Math.pow(beta1, adam.t);
    const bc2 = 1 - Math.pow(beta2, adam.t);

    const weightList = flattenWeightsList(this._model.weights);

    for (let t = 0; t < weightList.length; t++) {
      const w = weightList[t];
      const g = gradients[t];
      const m = adam.m[t];
      const v = adam.v[t];

      for (let i = 0; i < w.length; i++) {
        // Update moments
        m[i] = beta1 * m[i] + (1 - beta1) * g[i];
        v[i] = beta2 * v[i] + (1 - beta2) * g[i] * g[i];

        // Bias-corrected estimates
        const mHat = m[i] / bc1;
        const vHat = v[i] / bc2;

        // Update weight
        w[i] -= lr * mHat / (Math.sqrt(vHat) + eps);
      }
    }
  }

  /** Clip gradients by global L2 norm. */
  private _clipGradients(gradients: Float64Array[], maxNorm: number): void {
    let totalNormSq = 0;
    for (const g of gradients) {
      for (let i = 0; i < g.length; i++) totalNormSq += g[i] * g[i];
    }
    const totalNorm = Math.sqrt(totalNormSq);
    if (totalNorm > maxNorm) {
      const scale = maxNorm / totalNorm;
      for (const g of gradients) {
        for (let i = 0; i < g.length; i++) g[i] *= scale;
      }
    }
  }

  /** Shuffle array in-place (Fisher-Yates). Uses seeded PRNG when rngSeed is set. */
  private _shuffle<T>(arr: T[]): void {
    for (let i = arr.length - 1; i > 0; i--) {
      const r = this._rngState
        ? (xorshift32(this._rngState) >>> 0) / 0x100000000
        : Math.random();
      const j = Math.floor(r * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  }

  /** Sample n sequences randomly. */
  private _sampleSequences(seqs: string[][], n: number): string[][] {
    const copy = [...seqs];
    this._shuffle(copy);
    return copy.slice(0, n);
  }
}
