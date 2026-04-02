/**
 * Threat head classifier — three specialist attention heads that classify
 * tool calls by threat type: exfiltration, privilege escalation, reconnaissance.
 *
 * Each head is a 2-layer MLP (72→16→4) operating on:
 *   - finalLnOut (64-dim backbone embedding)
 *   - attention entropy per head (8-dim: 4 heads × 2 layers)
 *
 * Outputs are aggregated via reliability-weighted combination.
 *
 * ~3,720 parameters. Inference: <0.1ms on CPU.
 * Pure TypeScript, zero dependencies, Float64Array math.
 */

import { softmax, xorshift32, fnv1a } from "./linalg.js";

// ─── Types ───

/** Learned threat classes (per-head output). */
export enum LearnedThreatClass {
  ALIGNED = 0,
  TANGENT = 1,
  SUSPICIOUS = 2,
  HOSTILE = 3,
}

export const LEARNED_THREAT_CLASS_COUNT = 4;

/** Names for each specialist head. */
export type ThreatHeadName = "exfiltration" | "privilege_escalation" | "reconnaissance";

export const THREAT_HEAD_NAMES: ThreatHeadName[] = [
  "exfiltration",
  "privilege_escalation",
  "reconnaissance",
];

/** Input dimensions. */
const BACKBONE_DIM = 64;
const ENTROPY_DIM = 8; // 4 heads × 2 layers
const INPUT_DIM = BACKBONE_DIM + ENTROPY_DIM; // 72
const HIDDEN_DIM = 16;
const OUTPUT_DIM = LEARNED_THREAT_CLASS_COUNT; // 4
const NUM_HEADS = 3;

/** Weights for a single threat head MLP. */
export interface SingleHeadWeights {
  w1: Float64Array;  // INPUT_DIM × HIDDEN_DIM = 72×16 = 1152
  b1: Float64Array;  // HIDDEN_DIM = 16
  w2: Float64Array;  // HIDDEN_DIM × OUTPUT_DIM = 16×4 = 64
  b2: Float64Array;  // OUTPUT_DIM = 4
}

/** All threat head weights including aggregation. */
export interface ThreatHeadWeights {
  heads: SingleHeadWeights[];  // 3 heads
  /** Reliability scores for each head (EMA of accuracy). Used as aggregation weights. */
  reliability: Float64Array;   // 3 values
}

/** Prediction from a single threat head. */
export interface SingleHeadPrediction {
  name: ThreatHeadName;
  distribution: Float64Array;  // 4 probabilities (ALIGNED, TANGENT, SUSPICIOUS, HOSTILE)
  predicted: LearnedThreatClass;
}

/** Aggregated threat prediction from all heads. */
export interface ThreatPrediction {
  heads: SingleHeadPrediction[];
  /** Aggregated threat score: reliability-weighted max(SUSPICIOUS, HOSTILE) across heads. */
  threatScore: number;
  /** Dominant threat type (head name with highest threat contribution). */
  dominantThreatType: ThreatHeadName | null;
  /** Per-head reliability weights (softmax of reliability scores). */
  reliabilityWeights: Float64Array;
}

/** A labeled example for threat head training. */
export interface ThreatLabeledExample {
  /** Tool sequence (tool names). */
  sequence: string[];
  /** Intent vector (256-dim TF-IDF) or null. */
  intentVec: Float64Array | null;
  /** Per-head labels: [exfil_label, privesc_label, recon_label]. */
  headLabels: [LearnedThreatClass, LearnedThreatClass, LearnedThreatClass];
}

/** Cache for threat head forward pass (for backprop). */
interface HeadForwardCache {
  input: Float64Array;        // 72-dim
  hidden: Float64Array;       // 16-dim (pre-activation)
  hiddenAct: Float64Array;    // 16-dim (post-ReLU)
  logits: Float64Array;       // 4-dim
  probs: Float64Array;        // 4-dim (softmax)
}

// ─── Attention Entropy ───

/**
 * Compute Shannon entropy of each attention head at the last sequence position.
 * Returns 8-dim vector (4 heads × 2 layers).
 *
 * @param attnWeights - Per-layer attention weights from ForwardCache.layerCaches[l].attnWeights
 *                      Shape per layer: numHeads × seqLen × seqLen
 * @param numHeads - Number of attention heads (4)
 * @param numLayers - Number of layers (2)
 * @param seqLen - Sequence length
 */
export function attentionEntropy(
  layerAttnWeights: Float64Array[],
  numHeads: number,
  numLayers: number,
  seqLen: number,
): Float64Array {
  const result = new Float64Array(numHeads * numLayers);
  const lastPos = seqLen - 1;

  for (let l = 0; l < numLayers; l++) {
    const attnW = layerAttnWeights[l];
    for (let h = 0; h < numHeads; h++) {
      // Extract attention distribution at the last position for this head
      // attnW layout: head h, row lastPos → offset = h * seqLen * seqLen + lastPos * seqLen
      const offset = h * seqLen * seqLen + lastPos * seqLen;
      let ent = 0;
      // Only positions 0..lastPos are valid (causal mask zeros out the rest)
      for (let j = 0; j <= lastPos; j++) {
        const p = attnW[offset + j];
        if (p > 1e-12) {
          ent -= p * Math.log(p);
        }
      }
      result[l * numHeads + h] = ent;
    }
  }

  return result;
}

// ─── Threat Head Classifier ───

export class ThreatHeadClassifier {
  weights: ThreatHeadWeights;

  constructor(weights?: ThreatHeadWeights) {
    this.weights = weights || this._allocateWeights();
  }

  /** Initialize weights with Xavier initialization. */
  initWeights(seed = "shroud-threat-heads"): void {
    const rng = { s: fnv1a(seed) || 1 };
    const xavier = (fanIn: number, fanOut: number) => {
      const limit = Math.sqrt(6 / (fanIn + fanOut));
      return () => (xorshift32(rng) * 2 - 1) * limit;
    };

    for (let h = 0; h < NUM_HEADS; h++) {
      const head = this.weights.heads[h];
      const init1 = xavier(INPUT_DIM, HIDDEN_DIM);
      for (let i = 0; i < head.w1.length; i++) head.w1[i] = init1();
      // b1 = 0 (default)
      const init2 = xavier(HIDDEN_DIM, OUTPUT_DIM);
      for (let i = 0; i < head.w2.length; i++) head.w2[i] = init2();
      // b2 = 0 (default)
    }

    // Initialize reliability scores to equal (1.0 each — softmax gives 1/3)
    this.weights.reliability.fill(1.0);
  }

  /**
   * Forward pass through all three heads.
   * @param backboneEmb - 64-dim finalLnOut from transformer backbone
   * @param headEntropy - 8-dim attention entropy vector
   */
  forward(backboneEmb: Float64Array, headEntropy: Float64Array): ThreatPrediction {
    // Concatenate input: [backbone(64), entropy(8)] = 72
    const input = new Float64Array(INPUT_DIM);
    input.set(backboneEmb.subarray(0, BACKBONE_DIM), 0);
    input.set(headEntropy.subarray(0, ENTROPY_DIM), BACKBONE_DIM);

    const headPredictions: SingleHeadPrediction[] = [];
    for (let h = 0; h < NUM_HEADS; h++) {
      const cache = this._forwardHead(h, input);
      headPredictions.push({
        name: THREAT_HEAD_NAMES[h],
        distribution: cache.probs,
        predicted: this._argmax(cache.probs) as LearnedThreatClass,
      });
    }

    // Aggregate: reliability-weighted combination
    const relWeights = softmax(this.weights.reliability, NUM_HEADS);

    // Threat score: weighted sum of max(SUSPICIOUS, HOSTILE) from each head
    let threatScore = 0;
    let maxContribution = 0;
    let dominantIdx = -1;

    for (let h = 0; h < NUM_HEADS; h++) {
      const dist = headPredictions[h].distribution;
      const headThreat = dist[LearnedThreatClass.SUSPICIOUS] + dist[LearnedThreatClass.HOSTILE];
      const contribution = relWeights[h] * headThreat;
      threatScore += contribution;
      if (contribution > maxContribution) {
        maxContribution = contribution;
        dominantIdx = h;
      }
    }

    return {
      heads: headPredictions,
      threatScore,
      dominantThreatType: dominantIdx >= 0 && threatScore > 0.1
        ? THREAT_HEAD_NAMES[dominantIdx]
        : null,
      reliabilityWeights: relWeights,
    };
  }

  /**
   * Forward pass through a single head with cache for backprop.
   */
  forwardWithCache(headIdx: number, backboneEmb: Float64Array, headEntropy: Float64Array): HeadForwardCache {
    const input = new Float64Array(INPUT_DIM);
    input.set(backboneEmb.subarray(0, BACKBONE_DIM), 0);
    input.set(headEntropy.subarray(0, ENTROPY_DIM), BACKBONE_DIM);
    return this._forwardHead(headIdx, input);
  }

  /**
   * Backward pass for a single head. Returns weight gradients.
   * Cross-entropy loss: -log(probs[target]).
   */
  backwardHead(
    headIdx: number,
    cache: HeadForwardCache,
    target: LearnedThreatClass,
  ): SingleHeadWeights {
    const head = this.weights.heads[headIdx];
    const grad: SingleHeadWeights = {
      w1: new Float64Array(INPUT_DIM * HIDDEN_DIM),
      b1: new Float64Array(HIDDEN_DIM),
      w2: new Float64Array(HIDDEN_DIM * OUTPUT_DIM),
      b2: new Float64Array(OUTPUT_DIM),
    };

    // dLogits = probs - one_hot(target) (softmax + cross-entropy gradient)
    const dLogits = new Float64Array(OUTPUT_DIM);
    for (let i = 0; i < OUTPUT_DIM; i++) dLogits[i] = cache.probs[i];
    dLogits[target] -= 1;

    // dW2 = hiddenAct^T × dLogits
    for (let i = 0; i < HIDDEN_DIM; i++) {
      for (let j = 0; j < OUTPUT_DIM; j++) {
        grad.w2[i * OUTPUT_DIM + j] = cache.hiddenAct[i] * dLogits[j];
      }
    }
    // dB2 = dLogits
    for (let j = 0; j < OUTPUT_DIM; j++) grad.b2[j] = dLogits[j];

    // dHiddenAct = dLogits × W2^T
    const dHiddenAct = new Float64Array(HIDDEN_DIM);
    for (let i = 0; i < HIDDEN_DIM; i++) {
      for (let j = 0; j < OUTPUT_DIM; j++) {
        dHiddenAct[i] += dLogits[j] * head.w2[i * OUTPUT_DIM + j];
      }
    }

    // ReLU backward
    const dHidden = new Float64Array(HIDDEN_DIM);
    for (let i = 0; i < HIDDEN_DIM; i++) {
      dHidden[i] = cache.hidden[i] > 0 ? dHiddenAct[i] : 0;
    }

    // dW1 = input^T × dHidden
    for (let i = 0; i < INPUT_DIM; i++) {
      for (let j = 0; j < HIDDEN_DIM; j++) {
        grad.w1[i * HIDDEN_DIM + j] = cache.input[i] * dHidden[j];
      }
    }
    // dB1 = dHidden
    for (let j = 0; j < HIDDEN_DIM; j++) grad.b1[j] = dHidden[j];

    return grad;
  }

  /**
   * Update reliability scores based on observed accuracy.
   * Uses EMA: reliability = α * correct + (1 - α) * reliability.
   */
  updateReliability(headIdx: number, correct: boolean, alpha = 0.05): void {
    const val = correct ? 1.0 : 0.0;
    this.weights.reliability[headIdx] =
      alpha * val + (1 - alpha) * this.weights.reliability[headIdx];
  }

  /** Serialize weights to a flat Float64Array for persistence. */
  serialize(): Float64Array {
    const arrays = this._flattenWeights();
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Float64Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }

  /** Deserialize weights from a flat Float64Array. */
  deserialize(data: Float64Array): void {
    const arrays = this._flattenWeights();
    let offset = 0;
    for (const a of arrays) {
      for (let i = 0; i < a.length; i++) {
        a[i] = data[offset + i];
      }
      offset += a.length;
    }
  }

  /** Total parameter count. */
  paramCount(): number {
    // Per head: INPUT_DIM*HIDDEN_DIM + HIDDEN_DIM + HIDDEN_DIM*OUTPUT_DIM + OUTPUT_DIM
    //         = 72*16 + 16 + 16*4 + 4 = 1152 + 16 + 64 + 4 = 1236
    // 3 heads = 3708
    // Reliability: 3
    // Aggregation: 3
    // Total: 3714
    const arrays = this._flattenWeights();
    let total = 0;
    for (const a of arrays) total += a.length;
    return total;
  }

  // ─── Internal ───

  private _forwardHead(headIdx: number, input: Float64Array): HeadForwardCache {
    const head = this.weights.heads[headIdx];

    // Layer 1: input(72) × W1(72×16) + b1(16), then ReLU
    const hidden = new Float64Array(HIDDEN_DIM);
    for (let j = 0; j < HIDDEN_DIM; j++) {
      let sum = head.b1[j];
      for (let i = 0; i < INPUT_DIM; i++) {
        sum += input[i] * head.w1[i * HIDDEN_DIM + j];
      }
      hidden[j] = sum;
    }

    // ReLU
    const hiddenAct = new Float64Array(HIDDEN_DIM);
    for (let j = 0; j < HIDDEN_DIM; j++) {
      hiddenAct[j] = hidden[j] > 0 ? hidden[j] : 0;
    }

    // Layer 2: hiddenAct(16) × W2(16×4) + b2(4), then softmax
    const logits = new Float64Array(OUTPUT_DIM);
    for (let j = 0; j < OUTPUT_DIM; j++) {
      let sum = head.b2[j];
      for (let i = 0; i < HIDDEN_DIM; i++) {
        sum += hiddenAct[i] * head.w2[i * OUTPUT_DIM + j];
      }
      logits[j] = sum;
    }

    const probs = softmax(logits, OUTPUT_DIM);

    return { input, hidden, hiddenAct, logits, probs };
  }

  private _argmax(arr: Float64Array): number {
    let maxIdx = 0;
    for (let i = 1; i < arr.length; i++) {
      if (arr[i] > arr[maxIdx]) maxIdx = i;
    }
    return maxIdx;
  }

  private _allocateWeights(): ThreatHeadWeights {
    const heads: SingleHeadWeights[] = [];
    for (let h = 0; h < NUM_HEADS; h++) {
      heads.push({
        w1: new Float64Array(INPUT_DIM * HIDDEN_DIM),
        b1: new Float64Array(HIDDEN_DIM),
        w2: new Float64Array(HIDDEN_DIM * OUTPUT_DIM),
        b2: new Float64Array(OUTPUT_DIM),
      });
    }
    return {
      heads,
      reliability: new Float64Array(NUM_HEADS),
    };
  }

  private _flattenWeights(): Float64Array[] {
    const all: Float64Array[] = [];
    for (const h of this.weights.heads) {
      all.push(h.w1, h.b1, h.w2, h.b2);
    }
    all.push(this.weights.reliability);
    return all;
  }
}
