/**
 * Mini transformer — decoder-only, causal, pre-norm (GPT-2 style).
 *
 * 2 layers, 4 heads, hidden dim 64, FFN dim 256.
 * ~113K parameters. Inference: ~1-2ms on CPU for sequences ≤128.
 *
 * Pure TypeScript, zero dependencies.
 */

import {
  matmul, matmulTransB, matmulTransA, addBias,
  softmax, softmaxRows, layerNorm, gelu, geluBackward,
  layerNormBackward, crossEntropySoftmaxBackward,
  add, zeros, getRow, setRow, xorshift32, fnv1a,
  type LayerNormCache,
} from "./linalg.js";

// ─── Types ───

export interface TransformerConfig {
  vocabSize: number;     // max 128
  hiddenDim: number;     // 64
  numHeads: number;      // 4
  numLayers: number;     // 2
  ffnDim: number;        // 256
  maxSeqLen: number;     // 128
}

export interface LayerWeights {
  attnLnGamma: Float64Array;   // hiddenDim
  attnLnBeta: Float64Array;    // hiddenDim
  qProj: Float64Array;         // hiddenDim × hiddenDim
  kProj: Float64Array;         // hiddenDim × hiddenDim
  vProj: Float64Array;         // hiddenDim × hiddenDim
  oProj: Float64Array;         // hiddenDim × hiddenDim
  ffnLnGamma: Float64Array;    // hiddenDim
  ffnLnBeta: Float64Array;     // hiddenDim
  ffn1W: Float64Array;         // hiddenDim × ffnDim
  ffn1B: Float64Array;         // ffnDim
  ffn2W: Float64Array;         // ffnDim × hiddenDim
  ffn2B: Float64Array;         // hiddenDim
}

export interface TransformerWeights {
  tokenEmb: Float64Array;      // vocabSize × hiddenDim
  posEmb: Float64Array;        // maxSeqLen × hiddenDim
  layers: LayerWeights[];
  finalLnGamma: Float64Array;  // hiddenDim
  finalLnBeta: Float64Array;   // hiddenDim
  outProj: Float64Array;       // hiddenDim × vocabSize
  outBias: Float64Array;       // vocabSize
}

/** Forward pass cache for backpropagation. */
export interface ForwardCache {
  tokenIds: number[];
  seqLen: number;
  embedded: Float64Array;      // seqLen × hiddenDim
  layerCaches: LayerCache[];
  finalLnOut: Float64Array;
  finalLnCache: LayerNormCache;
  lastHidden: Float64Array;    // hiddenDim (last position)
  logits: Float64Array;        // vocabSize
  probs: Float64Array;         // vocabSize (softmax of logits)
}

interface LayerCache {
  input: Float64Array;          // seqLen × hiddenDim
  attnLnOut: Float64Array;      // seqLen × hiddenDim
  attnLnCaches: LayerNormCache[];
  Q: Float64Array;              // seqLen × hiddenDim
  K: Float64Array;
  V: Float64Array;
  attnWeights: Float64Array;    // numHeads × seqLen × seqLen
  attnOut: Float64Array;        // seqLen × hiddenDim
  attnProjOut: Float64Array;    // seqLen × hiddenDim
  postAttn: Float64Array;       // after residual add
  ffnLnOut: Float64Array;       // seqLen × hiddenDim
  ffnLnCaches: LayerNormCache[];
  ffn1Out: Float64Array;        // seqLen × ffnDim (pre-activation)
  ffn1Act: Float64Array;        // seqLen × ffnDim (post-GELU)
  ffn2Out: Float64Array;        // seqLen × hiddenDim
}

// ─── Default config ───

export const DEFAULT_CONFIG: TransformerConfig = {
  vocabSize: 128,
  hiddenDim: 64,
  numHeads: 4,
  numLayers: 2,
  ffnDim: 256,
  maxSeqLen: 128,
};

// ─── Model ───

export class MiniTransformer {
  readonly config: TransformerConfig;
  weights: TransformerWeights;

  constructor(config: TransformerConfig = DEFAULT_CONFIG) {
    this.config = config;
    this.weights = this._allocateWeights();
  }

  /** Initialize weights with Xavier/He initialization. */
  initWeights(seed = "shroud-transformer"): void {
    const rng = { s: fnv1a(seed) || 1 };
    const xavier = (fan: number) => {
      const limit = Math.sqrt(6 / fan);
      return () => (xorshift32(rng) * 2 - 1) * limit;
    };

    const { hiddenDim: d, ffnDim, vocabSize } = this.config;
    const w = this.weights;

    // Token embeddings: small random
    const embInit = xavier(d);
    for (let i = 0; i < w.tokenEmb.length; i++) w.tokenEmb[i] = embInit() * 0.02;

    // Positional embeddings: sinusoidal
    for (let pos = 0; pos < this.config.maxSeqLen; pos++) {
      for (let i = 0; i < d; i++) {
        const angle = pos / Math.pow(10000, (2 * Math.floor(i / 2)) / d);
        w.posEmb[pos * d + i] = i % 2 === 0 ? Math.sin(angle) : Math.cos(angle);
      }
    }

    // Layer weights
    for (const layer of w.layers) {
      // Attention projections: Xavier
      const attnInit = xavier(d + d);
      for (let i = 0; i < d * d; i++) {
        layer.qProj[i] = attnInit();
        layer.kProj[i] = attnInit();
        layer.vProj[i] = attnInit();
        layer.oProj[i] = attnInit();
      }
      // FFN: He init for first layer (through GELU)
      const ffn1Init = xavier(d + ffnDim);
      for (let i = 0; i < d * ffnDim; i++) layer.ffn1W[i] = ffn1Init();
      const ffn2Init = xavier(ffnDim + d);
      for (let i = 0; i < ffnDim * d; i++) layer.ffn2W[i] = ffn2Init();
      // Layer norm: gamma=1, beta=0
      layer.attnLnGamma.fill(1);
      layer.ffnLnGamma.fill(1);
      // Biases: zero (default)
    }

    // Final layer norm
    w.finalLnGamma.fill(1);

    // Output projection: Xavier
    const outInit = xavier(d + vocabSize);
    for (let i = 0; i < d * vocabSize; i++) w.outProj[i] = outInit();
  }

  /** Forward pass. Returns logits for the last position. */
  forward(tokenIds: number[]): Float64Array {
    return this.forwardFull(tokenIds).logits;
  }

  /** Predict next-token probabilities (softmax of logits). */
  predict(tokenIds: number[]): Float64Array {
    const logits = this.forward(tokenIds);
    return softmax(logits, this.config.vocabSize);
  }

  /** Forward pass with full cache for backpropagation. */
  forwardFull(tokenIds: number[]): ForwardCache {
    const { hiddenDim: d, numHeads, numLayers, ffnDim, vocabSize } = this.config;
    const T = tokenIds.length;
    const headDim = d / numHeads;
    const w = this.weights;

    // 1. Embedding: token + positional
    const embedded = new Float64Array(T * d);
    for (let t = 0; t < T; t++) {
      // Clamp token ID to vocab range (out-of-range tokens use ID 1 = UNK)
      const tokId = tokenIds[t] < vocabSize ? tokenIds[t] : 1;
      const tokOff = tokId * d;
      const posOff = t * d;
      const embOff = t * d;
      for (let i = 0; i < d; i++) {
        embedded[embOff + i] = w.tokenEmb[tokOff + i] + w.posEmb[posOff + i];
      }
    }

    // 2. Transformer layers
    let hidden = embedded;
    const layerCaches: LayerCache[] = [];

    for (let l = 0; l < numLayers; l++) {
      const lw = w.layers[l];
      const input = new Float64Array(hidden);

      // 2a. Pre-norm for attention
      const attnLnCaches: LayerNormCache[] = [];
      const attnLnOut = new Float64Array(T * d);
      for (let t = 0; t < T; t++) {
        const row = getRow(hidden, t, d);
        const { out, cache } = layerNorm(row, lw.attnLnGamma, lw.attnLnBeta, d);
        setRow(attnLnOut, t, d, out);
        attnLnCaches.push(cache);
      }

      // 2b. QKV projections: (T×d) × (d×d) = T×d
      const Q = matmul(attnLnOut, lw.qProj, T, d, d);
      const K = matmul(attnLnOut, lw.kProj, T, d, d);
      const V = matmul(attnLnOut, lw.vProj, T, d, d);

      // 2c. Multi-head attention with causal mask
      const attnOut = new Float64Array(T * d);
      const allAttnWeights = new Float64Array(numHeads * T * T);

      for (let h = 0; h < numHeads; h++) {
        // Extract head slices
        const Qh = new Float64Array(T * headDim);
        const Kh = new Float64Array(T * headDim);
        const Vh = new Float64Array(T * headDim);
        for (let t = 0; t < T; t++) {
          for (let i = 0; i < headDim; i++) {
            Qh[t * headDim + i] = Q[t * d + h * headDim + i];
            Kh[t * headDim + i] = K[t * d + h * headDim + i];
            Vh[t * headDim + i] = V[t * d + h * headDim + i];
          }
        }

        // Attention scores: Q @ K^T / sqrt(d_k)
        const scores = matmulTransB(Qh, Kh, T, headDim, T);
        const scale = 1 / Math.sqrt(headDim);
        for (let i = 0; i < scores.length; i++) scores[i] *= scale;

        // Causal mask: -1e9 for future positions
        for (let i = 0; i < T; i++) {
          for (let j = i + 1; j < T; j++) {
            scores[i * T + j] = -1e9;
          }
        }

        // Softmax per row
        const weights = softmaxRows(scores, T, T);

        // Store attention weights for cache
        allAttnWeights.set(weights, h * T * T);

        // Weighted sum of values: weights @ V
        const headOut = matmul(weights, Vh, T, T, headDim);

        // Write back to concatenated output
        for (let t = 0; t < T; t++) {
          for (let i = 0; i < headDim; i++) {
            attnOut[t * d + h * headDim + i] = headOut[t * headDim + i];
          }
        }
      }

      // 2d. Output projection
      const attnProjOut = matmul(attnOut, lw.oProj, T, d, d);

      // 2e. Residual add
      const postAttn = add(hidden, attnProjOut);

      // 2f. Pre-norm for FFN
      const ffnLnCaches: LayerNormCache[] = [];
      const ffnLnOut = new Float64Array(T * d);
      for (let t = 0; t < T; t++) {
        const row = getRow(postAttn, t, d);
        const { out, cache } = layerNorm(row, lw.ffnLnGamma, lw.ffnLnBeta, d);
        setRow(ffnLnOut, t, d, out);
        ffnLnCaches.push(cache);
      }

      // 2g. FFN: linear → GELU → linear
      const ffn1Out = matmul(ffnLnOut, lw.ffn1W, T, d, ffnDim);
      addBias(ffn1Out, lw.ffn1B, T, ffnDim);
      const ffn1Act = gelu(ffn1Out);
      const ffn2Out = matmul(ffn1Act, lw.ffn2W, T, ffnDim, d);
      addBias(ffn2Out, lw.ffn2B, T, d);

      // 2h. Residual add
      hidden = add(postAttn, ffn2Out);

      layerCaches.push({
        input, attnLnOut, attnLnCaches, Q, K, V,
        attnWeights: allAttnWeights, attnOut, attnProjOut,
        postAttn, ffnLnOut, ffnLnCaches,
        ffn1Out, ffn1Act, ffn2Out,
      });
    }

    // 3. Final layer norm (only on last position for efficiency)
    const lastHiddenRaw = getRow(hidden, T - 1, d);
    const { out: finalLnOut, cache: finalLnCache } = layerNorm(
      lastHiddenRaw, w.finalLnGamma, w.finalLnBeta, d,
    );

    // 4. Output projection → logits
    const logits = matmul(
      finalLnOut, w.outProj,
      1, d, vocabSize,
    );
    addBias(logits, w.outBias, 1, vocabSize);

    // 5. Softmax for probabilities
    const probs = softmax(logits, vocabSize);

    return {
      tokenIds, seqLen: T, embedded,
      layerCaches, finalLnOut, finalLnCache,
      lastHidden: lastHiddenRaw, logits, probs,
    };
  }

  /** Backward pass. Returns gradients for all weights. */
  backward(cache: ForwardCache, targetId: number): TransformerWeights {
    const { hiddenDim: d, numHeads, vocabSize, ffnDim } = this.config;
    const T = cache.seqLen;
    const headDim = d / numHeads;
    const w = this.weights;

    // Allocate gradient buffers (same shape as weights)
    const grad = this._allocateWeights();

    // ── Output layer ──
    // dLogits = probs - one_hot(target) (combined softmax + cross-entropy gradient)
    const dLogits = crossEntropySoftmaxBackward(cache.probs, targetId, vocabSize);

    // dOutBias = dLogits
    for (let i = 0; i < vocabSize; i++) grad.outBias[i] = dLogits[i];

    // dOutProj = finalLnOut^T × dLogits (1×d)^T × (1×vocab) = d×vocab
    for (let i = 0; i < d; i++) {
      for (let j = 0; j < vocabSize; j++) {
        grad.outProj[i * vocabSize + j] = cache.finalLnOut[i] * dLogits[j];
      }
    }

    // dFinalLnOut = dLogits × outProj^T (1×vocab) × (vocab×d) = 1×d
    const dFinalLnOut = new Float64Array(d);
    for (let i = 0; i < d; i++) {
      for (let j = 0; j < vocabSize; j++) {
        dFinalLnOut[i] += dLogits[j] * w.outProj[i * vocabSize + j];
      }
    }

    // ── Final layer norm backward ──
    const { dx: dLastHidden, dgamma: dFinalGamma, dbeta: dFinalBeta } = layerNormBackward(
      dFinalLnOut, cache.finalLnCache, w.finalLnGamma, d,
    );
    for (let i = 0; i < d; i++) {
      grad.finalLnGamma[i] = dFinalGamma[i];
      grad.finalLnBeta[i] = dFinalBeta[i];
    }

    // Expand to full sequence (only last position has gradient)
    const dHidden = new Float64Array(T * d);
    setRow(dHidden, T - 1, d, dLastHidden);

    // ── Transformer layers (reverse) ──
    let dH = dHidden;

    for (let l = this.config.numLayers - 1; l >= 0; l--) {
      const lw = w.layers[l];
      const lc = cache.layerCaches[l];
      const lg = grad.layers[l];

      // ── FFN residual backward ──
      // dPostAttn += dH (residual)
      // dFFN2Out = dH
      const dFFN2Out = new Float64Array(dH);

      // FFN2 backward: dFFN2Out → dFFN1Act, dFFN2W, dFFN2B
      // dFFN2B: sum over positions
      for (let t = 0; t < T; t++) {
        for (let i = 0; i < d; i++) {
          lg.ffn2B[i] += dFFN2Out[t * d + i];
        }
      }
      // dFFN2W = ffn1Act^T × dFFN2Out
      const dFFN2W = matmulTransA(lc.ffn1Act, dFFN2Out, T, ffnDim, d);
      for (let i = 0; i < dFFN2W.length; i++) lg.ffn2W[i] += dFFN2W[i];

      // dFFN1Act = dFFN2Out × ffn2W^T
      const dFFN1Act = matmulTransB(dFFN2Out, lw.ffn2W, T, d, ffnDim);

      // GELU backward
      const dFFN1Out = geluBackward(dFFN1Act, lc.ffn1Out);

      // FFN1 backward
      for (let t = 0; t < T; t++) {
        for (let i = 0; i < ffnDim; i++) {
          lg.ffn1B[i] += dFFN1Out[t * ffnDim + i];
        }
      }
      const dFFN1W = matmulTransA(lc.ffnLnOut, dFFN1Out, T, d, ffnDim);
      for (let i = 0; i < dFFN1W.length; i++) lg.ffn1W[i] += dFFN1W[i];

      // dFFNLnOut = dFFN1Out × ffn1W^T
      const dFFNLnOut = matmulTransB(dFFN1Out, lw.ffn1W, T, ffnDim, d);

      // FFN layer norm backward (per position)
      const dPostAttn = new Float64Array(dH); // starts with residual gradient
      for (let t = 0; t < T; t++) {
        const dRow = getRow(dFFNLnOut, t, d);
        const { dx, dgamma, dbeta } = layerNormBackward(
          dRow, lc.ffnLnCaches[t], lw.ffnLnGamma, d,
        );
        for (let i = 0; i < d; i++) {
          dPostAttn[t * d + i] += dx[i];
          lg.ffnLnGamma[i] += dgamma[i];
          lg.ffnLnBeta[i] += dbeta[i];
        }
      }

      // ── Attention residual backward ──
      // dInput += dPostAttn (residual)
      // dAttnProjOut = dPostAttn
      const dAttnProjOut = new Float64Array(dPostAttn);

      // Output projection backward
      const dAttnOut = matmulTransB(dAttnProjOut, lw.oProj, T, d, d);
      const dOProj = matmulTransA(lc.attnOut, dAttnProjOut, T, d, d);
      for (let i = 0; i < dOProj.length; i++) lg.oProj[i] += dOProj[i];

      // Multi-head attention backward
      const dQ = new Float64Array(T * d);
      const dK = new Float64Array(T * d);
      const dV = new Float64Array(T * d);

      for (let h = 0; h < numHeads; h++) {
        // Extract head gradients
        const dAttnOutH = new Float64Array(T * headDim);
        const Qh = new Float64Array(T * headDim);
        const Kh = new Float64Array(T * headDim);
        const Vh = new Float64Array(T * headDim);
        const weightsH = new Float64Array(T * T);

        for (let t = 0; t < T; t++) {
          for (let i = 0; i < headDim; i++) {
            dAttnOutH[t * headDim + i] = dAttnOut[t * d + h * headDim + i];
            Qh[t * headDim + i] = lc.Q[t * d + h * headDim + i];
            Kh[t * headDim + i] = lc.K[t * d + h * headDim + i];
            Vh[t * headDim + i] = lc.V[t * d + h * headDim + i];
          }
        }
        weightsH.set(lc.attnWeights.subarray(h * T * T, (h + 1) * T * T));

        // dV = weights^T × dAttnOutH
        const dVh = matmulTransA(weightsH, dAttnOutH, T, T, headDim);

        // dWeights = dAttnOutH × V^T
        const dWeights = matmulTransB(dAttnOutH, Vh, T, headDim, T);

        // Softmax backward: dScores = weights * (dWeights - sum(dWeights * weights))
        const dScores = new Float64Array(T * T);
        for (let i = 0; i < T; i++) {
          let dotSum = 0;
          for (let j = 0; j < T; j++) {
            dotSum += dWeights[i * T + j] * weightsH[i * T + j];
          }
          for (let j = 0; j < T; j++) {
            dScores[i * T + j] = weightsH[i * T + j] * (dWeights[i * T + j] - dotSum);
          }
        }

        // Scale backward
        const scale = 1 / Math.sqrt(headDim);
        for (let i = 0; i < dScores.length; i++) dScores[i] *= scale;

        // Causal mask: zero out gradient for masked positions
        for (let i = 0; i < T; i++) {
          for (let j = i + 1; j < T; j++) {
            dScores[i * T + j] = 0;
          }
        }

        // dQ = dScores × K
        const dQh = matmul(dScores, Kh, T, T, headDim);

        // dK = dScores^T × Q
        const dKh = matmulTransA(dScores, Qh, T, T, headDim);

        // Write head gradients back
        for (let t = 0; t < T; t++) {
          for (let i = 0; i < headDim; i++) {
            dQ[t * d + h * headDim + i] += dQh[t * headDim + i];
            dK[t * d + h * headDim + i] += dKh[t * headDim + i];
            dV[t * d + h * headDim + i] += dVh[t * headDim + i];
          }
        }
      }

      // QKV projection backward
      const dAttnLnOut = new Float64Array(T * d);
      const dQProj = matmulTransA(lc.attnLnOut, dQ, T, d, d);
      const dKProj = matmulTransA(lc.attnLnOut, dK, T, d, d);
      const dVProj = matmulTransA(lc.attnLnOut, dV, T, d, d);
      for (let i = 0; i < dQProj.length; i++) lg.qProj[i] += dQProj[i];
      for (let i = 0; i < dKProj.length; i++) lg.kProj[i] += dKProj[i];
      for (let i = 0; i < dVProj.length; i++) lg.vProj[i] += dVProj[i];

      // dAttnLnOut += dQ × qProj^T + dK × kProj^T + dV × vProj^T
      const dQ2 = matmulTransB(dQ, lw.qProj, T, d, d);
      const dK2 = matmulTransB(dK, lw.kProj, T, d, d);
      const dV2 = matmulTransB(dV, lw.vProj, T, d, d);
      for (let i = 0; i < dAttnLnOut.length; i++) {
        dAttnLnOut[i] = dQ2[i] + dK2[i] + dV2[i];
      }

      // Attention layer norm backward
      const dInput = new Float64Array(dPostAttn); // residual gradient
      for (let t = 0; t < T; t++) {
        const dRow = getRow(dAttnLnOut, t, d);
        const { dx, dgamma, dbeta } = layerNormBackward(
          dRow, lc.attnLnCaches[t], lw.attnLnGamma, d,
        );
        for (let i = 0; i < d; i++) {
          dInput[t * d + i] += dx[i];
          lg.attnLnGamma[i] += dgamma[i];
          lg.attnLnBeta[i] += dbeta[i];
        }
      }

      dH = dInput;
    }

    // ── Embedding gradients ──
    for (let t = 0; t < T; t++) {
      const tokId = cache.tokenIds[t];
      for (let i = 0; i < d; i++) {
        grad.tokenEmb[tokId * d + i] += dH[t * d + i];
        grad.posEmb[t * d + i] += dH[t * d + i];
      }
    }

    return grad;
  }

  // ─── Serialization ───

  /** Serialize all weights to a flat Buffer. */
  serializeWeights(): Buffer {
    const tensors = this._flattenWeights(this.weights);
    let totalLen = 0;
    for (const t of tensors) totalLen += t.length;
    const buf = Buffer.alloc(totalLen * 8);
    let offset = 0;
    for (const t of tensors) {
      for (let i = 0; i < t.length; i++) {
        buf.writeDoubleBE(t[i], offset);
        offset += 8;
      }
    }
    return buf;
  }

  /** Deserialize weights from a flat Buffer. */
  deserializeWeights(buf: Buffer): void {
    const tensors = this._flattenWeights(this.weights);
    let offset = 0;
    for (const t of tensors) {
      for (let i = 0; i < t.length; i++) {
        t[i] = buf.readDoubleBE(offset);
        offset += 8;
      }
    }
  }

  /** Count total parameters. */
  paramCount(): number {
    const tensors = this._flattenWeights(this.weights);
    let total = 0;
    for (const t of tensors) total += t.length;
    return total;
  }

  // ─── Internal ───

  private _allocateWeights(): TransformerWeights {
    const { vocabSize, hiddenDim: d, numHeads, numLayers, ffnDim, maxSeqLen } = this.config;
    const layers: LayerWeights[] = [];
    for (let i = 0; i < numLayers; i++) {
      layers.push({
        attnLnGamma: new Float64Array(d),
        attnLnBeta: new Float64Array(d),
        qProj: new Float64Array(d * d),
        kProj: new Float64Array(d * d),
        vProj: new Float64Array(d * d),
        oProj: new Float64Array(d * d),
        ffnLnGamma: new Float64Array(d),
        ffnLnBeta: new Float64Array(d),
        ffn1W: new Float64Array(d * ffnDim),
        ffn1B: new Float64Array(ffnDim),
        ffn2W: new Float64Array(ffnDim * d),
        ffn2B: new Float64Array(d),
      });
    }
    return {
      tokenEmb: new Float64Array(vocabSize * d),
      posEmb: new Float64Array(maxSeqLen * d),
      layers,
      finalLnGamma: new Float64Array(d),
      finalLnBeta: new Float64Array(d),
      outProj: new Float64Array(d * vocabSize),
      outBias: new Float64Array(vocabSize),
    };
  }

  /** Flatten all weight tensors into an ordered list (for serialization). */
  private _flattenWeights(w: TransformerWeights): Float64Array[] {
    const all: Float64Array[] = [w.tokenEmb, w.posEmb];
    for (const l of w.layers) {
      all.push(
        l.attnLnGamma, l.attnLnBeta,
        l.qProj, l.kProj, l.vProj, l.oProj,
        l.ffnLnGamma, l.ffnLnBeta,
        l.ffn1W, l.ffn1B, l.ffn2W, l.ffn2B,
      );
    }
    all.push(w.finalLnGamma, w.finalLnBeta, w.outProj, w.outBias);
    return all;
  }
}

/** Add gradients to target weights: target += grad * scale. Mutates target. */
export function addGradients(
  target: TransformerWeights, grad: TransformerWeights,
  scale: number, targetList?: Float64Array[], gradList?: Float64Array[],
): void {
  const tl = targetList || flattenWeightsList(target);
  const gl = gradList || flattenWeightsList(grad);
  for (let t = 0; t < tl.length; t++) {
    const tw = tl[t];
    const gw = gl[t];
    for (let i = 0; i < tw.length; i++) {
      tw[i] += gw[i] * scale;
    }
  }
}

/** Flatten weights into ordered list (standalone version for optimizer). */
export function flattenWeightsList(w: TransformerWeights): Float64Array[] {
  const all: Float64Array[] = [w.tokenEmb, w.posEmb];
  for (const l of w.layers) {
    all.push(
      l.attnLnGamma, l.attnLnBeta,
      l.qProj, l.kProj, l.vProj, l.oProj,
      l.ffnLnGamma, l.ffnLnBeta,
      l.ffn1W, l.ffn1B, l.ffn2W, l.ffn2B,
    );
  }
  all.push(w.finalLnGamma, w.finalLnBeta, w.outProj, w.outBias);
  return all;
}
