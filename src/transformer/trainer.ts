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
import { crossEntropyLoss } from "./linalg.js";

// ─── Types ───

export interface TrainerConfig {
  learningRate: number;          // 0.001
  minLearningRate: number;       // 0.0001
  batchSize: number;             // 8
  maxEpochs: number;             // 10
  warmupSteps: number;           // 50
  maxSequences: number;          // 500 (sample if store is larger)
  gradClipNorm: number;          // 1.0
}

export interface TrainResult {
  finalLoss: number;
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

  constructor(
    model: MiniTransformer,
    tokenizer: ToolTokenizer,
    config: TrainerConfig = DEFAULT_TRAINER_CONFIG,
  ) {
    this._model = model;
    this._tokenizer = tokenizer;
    this._config = config;
  }

  /**
   * Train on a list of tool-call sequences (from VectorStore workflows).
   * Each sequence is a string[] of tool names.
   */
  trainOnSequences(sequences: string[][]): TrainResult {
    const start = Date.now();
    const cfg = this._config;

    // Filter sequences with at least 2 tools (need input + target)
    let data = sequences.filter(s => s.length >= 2);
    if (data.length === 0) return { finalLoss: 0, epochs: 0, totalSteps: 0, durationMs: 0, sequencesUsed: 0 };

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

    // Prepare training examples: (prefix, target) pairs
    const examples: Array<{ input: number[]; target: number }> = [];
    for (const seq of data) {
      const encoded = this._tokenizer.encodeSequence(seq);
      // For each position i (starting from 1, since 0 is BOS), predict position i+1
      for (let i = 1; i < encoded.length - 1; i++) {
        examples.push({
          input: encoded.slice(0, i + 1),     // [BOS, tool_0, ..., tool_i]
          target: encoded[i + 1],             // tool_{i+1}
        });
      }
    }

    if (examples.length === 0) return { finalLoss: 0, epochs: 0, totalSteps: 0, durationMs: 0, sequencesUsed: data.length };

    // Initialize Adam state
    if (!this._adamState) {
      this._adamState = createAdamState(this._model.weights);
    }

    const totalSteps = Math.ceil(examples.length / cfg.batchSize) * cfg.maxEpochs;
    let step = 0;
    let lastLoss = 0;

    for (let epoch = 0; epoch < cfg.maxEpochs; epoch++) {
      // Shuffle examples
      this._shuffle(examples);

      let epochLoss = 0;
      let epochCount = 0;

      for (let b = 0; b < examples.length; b += cfg.batchSize) {
        const batchEnd = Math.min(b + cfg.batchSize, examples.length);
        const batchSize = batchEnd - b;

        // Accumulate gradients across the batch
        const accumGrad = this._model["_allocateWeights"]();
        let batchLoss = 0;

        for (let i = b; i < batchEnd; i++) {
          const { input, target } = examples[i];

          // Forward pass
          const cache = this._model.forwardFull(input);
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

    return {
      finalLoss: lastLoss,
      epochs: cfg.maxEpochs,
      totalSteps: step,
      durationMs: Date.now() - start,
      sequencesUsed: data.length,
    };
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

  /** Shuffle array in-place (Fisher-Yates). */
  private _shuffle<T>(arr: T[]): void {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
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
