/**
 * Contrastive learning on tool-call pairs (Tier 2).
 *
 * Uses triplet loss to train the shared transformer backbone so that
 * embeddings of legitimate tool sequences are far from hijacked sequences.
 *
 * Attack traces come from three sources:
 *   1. Shadow execution — hijacked trajectories observed in simulation
 *   2. Honeypot triggers — confirmed injection via fake credential tripwires
 *   3. Phantom tool triggers — canary tools invoked by injected prompts
 *
 * The contrastive objective is auxiliary: it runs after the main cross-entropy
 * training loop, sharing the backbone weights. No new parameters are added.
 *
 * Zero external dependencies. Pure TypeScript, Float64Array math.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { MiniTransformer, flattenWeightsList, type ForwardCache } from "./model.js";
import { ToolTokenizer, BOS } from "./tokenizer.js";
import { l2Distance, l2Normalize } from "./linalg.js";

// ─── Types ───

export type AttackTraceSource = "shadow" | "honeypot" | "phantom";

/** A recorded attack trace: legitimate prefix hijacked into malicious suffix. */
export interface AttackTrace {
  /** Tool names before the injection point. */
  legitimatePrefix: string[];
  /** Tool names after the injection point (the attack). */
  hijackedSuffix: string[];
  /** Index in the original sequence where injection occurred. */
  injectionPoint: number;
  /** Where this trace came from. */
  source: AttackTraceSource;
  /** Threat classification string (e.g. "shadow_exfil", "honeypot_credential"). */
  threatType: string;
  /** Timestamp when the trace was recorded. */
  timestamp?: number;
}

// ─── Attack Trace Store ───

const MAX_TRACES = 500;

/** In-memory ring buffer for attack traces, with disk persistence. */
export class AttackTraceStore {
  private _traces: AttackTrace[] = [];
  private _profileDir: string;

  constructor(profileDir: string) {
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
  }

  /** Add a trace. Evicts oldest when buffer is full. */
  add(trace: AttackTrace): void {
    if (!trace.timestamp) trace.timestamp = Date.now();
    if (this._traces.length >= MAX_TRACES) {
      this._traces.shift();
    }
    this._traces.push(trace);
  }

  /** Get all stored traces. */
  getAll(): AttackTrace[] {
    return this._traces;
  }

  /** Number of stored traces. */
  count(): number {
    return this._traces.length;
  }

  /** Load traces from disk. Returns true on success. */
  load(): boolean {
    try {
      const path = join(this._profileDir, "attack-traces.json");
      if (!existsSync(path)) return false;
      const data = JSON.parse(readFileSync(path, "utf-8"));
      if (Array.isArray(data)) {
        this._traces = data.slice(-MAX_TRACES);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /** Save traces to disk. */
  save(): void {
    try {
      mkdirSync(this._profileDir, { recursive: true });
      writeFileSync(
        join(this._profileDir, "attack-traces.json"),
        JSON.stringify(this._traces),
        "utf-8",
      );
    } catch {
      // Best-effort persistence
    }
  }
}

// ─── Triplet Loss ───

/**
 * Triplet loss with margin: max(0, d(anchor, positive)^2 - d(anchor, negative)^2 + margin).
 *
 * Returns the loss value and gradients for anchor, positive, and negative vectors.
 * All vectors must have the same dimension.
 */
export function tripletLoss(
  anchor: Float64Array,
  positive: Float64Array,
  negative: Float64Array,
  margin: number,
  dim: number,
): { loss: number; dAnchor: Float64Array; dPositive: Float64Array; dNegative: Float64Array } {
  // Squared L2 distances
  let dPosSq = 0;
  let dNegSq = 0;
  for (let i = 0; i < dim; i++) {
    const dp = anchor[i] - positive[i];
    const dn = anchor[i] - negative[i];
    dPosSq += dp * dp;
    dNegSq += dn * dn;
  }

  const rawLoss = dPosSq - dNegSq + margin;
  const loss = Math.max(0, rawLoss);

  const dAnchor = new Float64Array(dim);
  const dPositive = new Float64Array(dim);
  const dNegative = new Float64Array(dim);

  // Gradients are non-zero only when loss > 0 (margin violated)
  if (rawLoss > 0) {
    for (let i = 0; i < dim; i++) {
      // d/dA (||A-P||^2 - ||A-N||^2) = 2(A-P) - 2(A-N) = 2(N-P)
      dAnchor[i] = 2 * ((anchor[i] - positive[i]) - (anchor[i] - negative[i]));
      // d/dP (||A-P||^2) = -2(A-P) = 2(P-A)
      dPositive[i] = -2 * (anchor[i] - positive[i]);
      // d/dN (-||A-N||^2) = 2(A-N)
      dNegative[i] = 2 * (anchor[i] - negative[i]);
    }
  }

  return { loss, dAnchor, dPositive, dNegative };
}

// ─── Contrastive Trainer ───

export interface ContrastiveConfig {
  /** Triplet loss margin. */
  margin: number;
  /** Learning rate for contrastive updates. */
  learningRate: number;
  /** Max triplets to sample per training round. */
  maxTriplets: number;
  /** Weight for contrastive loss relative to cross-entropy (lambda). */
  lambda: number;
}

export const DEFAULT_CONTRASTIVE_CONFIG: ContrastiveConfig = {
  margin: 1.0,
  learningRate: 0.0005,
  maxTriplets: 32,
  lambda: 0.3,
};

/**
 * Contrastive trainer — uses triplet loss through the shared transformer backbone.
 *
 * Triplet sampling:
 *   - Anchor: legitimate prefix (healthy workflow)
 *   - Positive: another healthy workflow with similar prefix
 *   - Negative: hijacked suffix from an attack trace
 */
export class ContrastiveTrainer {
  private _model: MiniTransformer;
  private _tokenizer: ToolTokenizer;
  private _config: ContrastiveConfig;

  constructor(
    model: MiniTransformer,
    tokenizer: ToolTokenizer,
    config: ContrastiveConfig = DEFAULT_CONTRASTIVE_CONFIG,
  ) {
    this._model = model;
    this._tokenizer = tokenizer;
    this._config = config;
  }

  /**
   * Run contrastive mini-batches using attack traces + healthy workflows.
   *
   * Returns total contrastive loss and number of triplets processed.
   */
  async trainOnTraces(
    attackTraces: AttackTrace[],
    healthyWorkflows: string[][],
    intentVecs?: Array<Float64Array | null>,
  ): Promise<{ loss: number; triplets: number }> {
    if (attackTraces.length === 0 || healthyWorkflows.length < 2) {
      return { loss: 0, triplets: 0 };
    }

    // Ensure all tools are in the tokenizer
    for (const trace of attackTraces) {
      for (const t of trace.legitimatePrefix) this._tokenizer.addTool(t);
      for (const t of trace.hijackedSuffix) this._tokenizer.addTool(t);
    }
    for (const wf of healthyWorkflows) {
      for (const t of wf) this._tokenizer.addTool(t);
    }

    const dim = this._model.config.hiddenDim;
    let totalLoss = 0;
    let tripletCount = 0;

    // Sample triplets
    const maxTriplets = Math.min(this._config.maxTriplets, attackTraces.length * healthyWorkflows.length);

    for (let t = 0; t < maxTriplets; t++) {
      // Yield every 4 triplets to keep the event loop responsive
      if (t > 0 && t % 4 === 0) await new Promise<void>(r => setImmediate(r));
      // Pick an attack trace
      const traceIdx = t % attackTraces.length;
      const trace = attackTraces[traceIdx];

      // Anchor: the legitimate prefix from the attack trace
      const anchorSeq = trace.legitimatePrefix;
      if (anchorSeq.length < 2) continue;

      // Positive: a random healthy workflow (different from anchor)
      const posIdx = (t * 7 + 13) % healthyWorkflows.length; // deterministic spread
      const positiveSeq = healthyWorkflows[posIdx];
      if (positiveSeq.length < 2) continue;

      // Negative: the full attack sequence (prefix + hijacked suffix)
      const negativeSeq = [...trace.legitimatePrefix, ...trace.hijackedSuffix];
      if (negativeSeq.length < 2) continue;

      // Get embeddings (forward passes through the shared backbone)
      const anchorIntentVec = intentVecs ? intentVecs[0] || null : null;
      const anchorEmb = this._model.getEmbedding(
        this._tokenizer.encodeSequence(anchorSeq),
        anchorIntentVec,
      );
      const positiveEmb = this._model.getEmbedding(
        this._tokenizer.encodeSequence(positiveSeq),
        intentVecs ? intentVecs[posIdx % intentVecs.length] || null : null,
      );
      const negativeEmb = this._model.getEmbedding(
        this._tokenizer.encodeSequence(negativeSeq),
        null, // attack sequences have no user intent
      );

      // Compute triplet loss
      const tl = tripletLoss(anchorEmb, positiveEmb, negativeEmb, this._config.margin, dim);
      if (tl.loss === 0) continue; // margin satisfied, skip

      totalLoss += tl.loss;
      tripletCount++;

      // Backward through each branch and apply gradients
      // Anchor
      this._backwardAndApply(anchorSeq, anchorIntentVec, tl.dAnchor);
      // Positive
      this._backwardAndApply(
        positiveSeq,
        intentVecs ? intentVecs[posIdx % intentVecs.length] || null : null,
        tl.dPositive,
      );
      // Negative
      this._backwardAndApply(negativeSeq, null, tl.dNegative);
    }

    return { loss: totalLoss, triplets: tripletCount };
  }

  /** Run forward pass, compute embedding gradient backward, and apply weight update. */
  private _backwardAndApply(
    sequence: string[],
    intentVec: Float64Array | null,
    dEmbedding: Float64Array,
  ): void {
    const tokenIds = this._tokenizer.encodeSequence(sequence);

    // Truncate if too long
    if (tokenIds.length > this._model.config.maxSeqLen) {
      tokenIds.splice(0, tokenIds.length - this._model.config.maxSeqLen);
    }

    const cache = this._model.forwardFull(tokenIds, intentVec);

    // Backward from embedding through the backbone (skips output projection)
    const grad = this._model.backwardContrastive(cache, dEmbedding);

    // Apply gradients with contrastive learning rate scaled by lambda
    const lr = this._config.learningRate * this._config.lambda;
    const wList = flattenWeightsList(this._model.weights);
    const gList = flattenWeightsList(grad);
    for (let i = 0; i < wList.length; i++) {
      const w = wList[i];
      const g = gList[i];
      for (let j = 0; j < w.length; j++) {
        w[j] -= lr * g[j];
      }
    }
  }
}
