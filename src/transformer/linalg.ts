/**
 * Linear algebra primitives for the mini transformer.
 *
 * All operations work on flat Float64Array with explicit dimensions.
 * Row-major layout: element (i, j) of an M×N matrix is at index i*N + j.
 *
 * Zero external dependencies — pure math on typed arrays.
 */

// ─── Matrix operations ───

/** Matrix multiply: C = A(M×K) × B(K×N). Returns new M×N array. */
export function matmul(
  A: Float64Array, B: Float64Array,
  M: number, K: number, N: number,
): Float64Array {
  const C = new Float64Array(M * N);
  for (let i = 0; i < M; i++) {
    const iK = i * K;
    const iN = i * N;
    for (let k = 0; k < K; k++) {
      const a = A[iK + k];
      if (a === 0) continue;
      const kN = k * N;
      for (let j = 0; j < N; j++) {
        C[iN + j] += a * B[kN + j];
      }
    }
  }
  return C;
}

/** C = A(M×K) × B^T(N×K). B is N×K, treated as transposed. Returns M×N. */
export function matmulTransB(
  A: Float64Array, B: Float64Array,
  M: number, K: number, N: number,
): Float64Array {
  const C = new Float64Array(M * N);
  for (let i = 0; i < M; i++) {
    const iK = i * K;
    const iN = i * N;
    for (let j = 0; j < N; j++) {
      const jK = j * K;
      let sum = 0;
      for (let k = 0; k < K; k++) {
        sum += A[iK + k] * B[jK + k];
      }
      C[iN + j] = sum;
    }
  }
  return C;
}

/** C = A^T(K×M) × B(K×N). A is K×M, treated as transposed. Returns M×N. */
export function matmulTransA(
  A: Float64Array, B: Float64Array,
  K: number, M: number, N: number,
): Float64Array {
  const C = new Float64Array(M * N);
  for (let k = 0; k < K; k++) {
    const kM = k * M;
    const kN = k * N;
    for (let i = 0; i < M; i++) {
      const a = A[kM + i];
      if (a === 0) continue;
      const iN = i * N;
      for (let j = 0; j < N; j++) {
        C[iN + j] += a * B[kN + j];
      }
    }
  }
  return C;
}

/** Add bias vector to each row: out[i][j] += bias[j]. Mutates out. */
export function addBias(out: Float64Array, bias: Float64Array, rows: number, cols: number): void {
  for (let i = 0; i < rows; i++) {
    const off = i * cols;
    for (let j = 0; j < cols; j++) {
      out[off + j] += bias[j];
    }
  }
}

// ─── Activation functions ───

/** GELU activation (tanh approximation). Returns new array. */
export function gelu(x: Float64Array): Float64Array {
  const out = new Float64Array(x.length);
  for (let i = 0; i < x.length; i++) {
    const v = x[i];
    // GELU(x) = 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x³)))
    const t = Math.tanh(0.7978845608 * (v + 0.044715 * v * v * v));
    out[i] = 0.5 * v * (1 + t);
  }
  return out;
}

/** GELU backward: dout * GELU'(x). */
export function geluBackward(dout: Float64Array, x: Float64Array): Float64Array {
  const dx = new Float64Array(x.length);
  for (let i = 0; i < x.length; i++) {
    const v = x[i];
    const c = 0.7978845608;
    const inner = c * (v + 0.044715 * v * v * v);
    const t = Math.tanh(inner);
    const sech2 = 1 - t * t;
    const dInner = c * (1 + 3 * 0.044715 * v * v);
    dx[i] = dout[i] * (0.5 * (1 + t) + 0.5 * v * sech2 * dInner);
  }
  return dx;
}

// ─── Softmax ───

/** Softmax over a 1D array of length `len`. Returns new array. */
export function softmax(logits: Float64Array, len: number): Float64Array {
  const out = new Float64Array(len);
  let max = -Infinity;
  for (let i = 0; i < len; i++) if (logits[i] > max) max = logits[i];
  let sum = 0;
  for (let i = 0; i < len; i++) {
    out[i] = Math.exp(logits[i] - max);
    sum += out[i];
  }
  for (let i = 0; i < len; i++) out[i] /= sum;
  return out;
}

/** Row-wise softmax on a rows×cols matrix. Returns new array. */
export function softmaxRows(logits: Float64Array, rows: number, cols: number): Float64Array {
  const out = new Float64Array(logits.length);
  for (let r = 0; r < rows; r++) {
    const off = r * cols;
    let max = -Infinity;
    for (let c = 0; c < cols; c++) if (logits[off + c] > max) max = logits[off + c];
    let sum = 0;
    for (let c = 0; c < cols; c++) {
      out[off + c] = Math.exp(logits[off + c] - max);
      sum += out[off + c];
    }
    for (let c = 0; c < cols; c++) out[off + c] /= sum;
  }
  return out;
}

// ─── Layer normalization ───

export interface LayerNormCache {
  mean: number;
  rstd: number;
  xNorm: Float64Array;
}

/** Layer norm: y = gamma * (x - mean) / sqrt(var + eps) + beta. Returns { out, cache }. */
export function layerNorm(
  x: Float64Array, gamma: Float64Array, beta: Float64Array,
  len: number, eps = 1e-5,
): { out: Float64Array; cache: LayerNormCache } {
  let mean = 0;
  for (let i = 0; i < len; i++) mean += x[i];
  mean /= len;

  let variance = 0;
  for (let i = 0; i < len; i++) {
    const d = x[i] - mean;
    variance += d * d;
  }
  variance /= len;
  const rstd = 1 / Math.sqrt(variance + eps);

  const out = new Float64Array(len);
  const xNorm = new Float64Array(len);
  for (let i = 0; i < len; i++) {
    xNorm[i] = (x[i] - mean) * rstd;
    out[i] = gamma[i] * xNorm[i] + beta[i];
  }

  return { out, cache: { mean, rstd, xNorm } };
}

/** Layer norm backward. Returns gradients for x, gamma, beta. */
export function layerNormBackward(
  dout: Float64Array, cache: LayerNormCache,
  gamma: Float64Array, len: number,
): { dx: Float64Array; dgamma: Float64Array; dbeta: Float64Array } {
  const { rstd, xNorm } = cache;
  const dgamma = new Float64Array(len);
  const dbeta = new Float64Array(len);
  const dx = new Float64Array(len);

  // dgamma = sum(dout * xNorm), dbeta = sum(dout)
  for (let i = 0; i < len; i++) {
    dgamma[i] = dout[i] * xNorm[i];
    dbeta[i] = dout[i];
  }

  // dx
  let dxNormSum = 0;
  let dxNormXNormSum = 0;
  for (let i = 0; i < len; i++) {
    const dxNorm = dout[i] * gamma[i];
    dxNormSum += dxNorm;
    dxNormXNormSum += dxNorm * xNorm[i];
  }
  for (let i = 0; i < len; i++) {
    const dxNorm = dout[i] * gamma[i];
    dx[i] = rstd * (dxNorm - (dxNormSum + xNorm[i] * dxNormXNormSum) / len);
  }

  return { dx, dgamma, dbeta };
}

// ─── Loss functions ───

/** Cross-entropy loss: -log(probs[targetIdx]). */
export function crossEntropyLoss(probs: Float64Array, targetIdx: number): number {
  return -Math.log(Math.max(probs[targetIdx], 1e-12));
}

/** Cross-entropy backward through softmax: dlogits = probs - one_hot(target). */
export function crossEntropySoftmaxBackward(
  probs: Float64Array, targetIdx: number, vocabSize: number,
): Float64Array {
  const dlogits = new Float64Array(vocabSize);
  for (let i = 0; i < vocabSize; i++) dlogits[i] = probs[i];
  dlogits[targetIdx] -= 1;
  return dlogits;
}

// ─── Utility ───

/** Element-wise add: out = a + b. Returns new array. */
export function add(a: Float64Array, b: Float64Array): Float64Array<ArrayBuffer> {
  const out = new Float64Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] + b[i];
  return out;
}

/** Scale array in place: x *= s. */
export function scaleInPlace(x: Float64Array, s: number): void {
  for (let i = 0; i < x.length; i++) x[i] *= s;
}

/** Zero-fill a Float64Array. */
export function zeros(len: number): Float64Array {
  return new Float64Array(len);
}

/** Extract a slice from a flat 2D array: row `r` of an M×N matrix. */
export function getRow(mat: Float64Array, r: number, cols: number): Float64Array {
  return mat.slice(r * cols, (r + 1) * cols);
}

/** Set a row in a flat 2D array. Mutates mat. */
export function setRow(mat: Float64Array, r: number, cols: number, row: Float64Array): void {
  mat.set(row, r * cols);
}

/** Deterministic PRNG (xorshift32). Same as pca.ts for consistency. */
export function xorshift32(state: { s: number }): number {
  let s = state.s;
  s ^= s << 13;
  s ^= s >>> 17;
  s ^= s << 5;
  state.s = s;
  return (s >>> 0) / 0xFFFFFFFF;
}

/** L2 (Euclidean) distance between two vectors. */
export function l2Distance(a: Float64Array, b: Float64Array, dim: number): number {
  let sum = 0;
  for (let i = 0; i < dim; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

/** L2-normalize a vector. Returns new array. */
export function l2Normalize(x: Float64Array, dim: number): Float64Array {
  const out = new Float64Array(dim);
  let norm = 0;
  for (let i = 0; i < dim; i++) norm += x[i] * x[i];
  norm = Math.sqrt(norm);
  if (norm < 1e-12) return out; // zero vector stays zero
  for (let i = 0; i < dim; i++) out[i] = x[i] / norm;
  return out;
}

/** Cosine similarity between two vectors. */
export function cosineSimilarity(a: Float64Array, b: Float64Array, dim: number): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < dim; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (denom < 1e-12) return 0;
  return dot / denom;
}

/** Shannon entropy of a probability distribution. H = -Σ p_i * log(p_i). */
export function entropy(probs: Float64Array, len: number): number {
  let h = 0;
  for (let i = 0; i < len; i++) {
    if (probs[i] > 1e-12) {
      h -= probs[i] * Math.log(probs[i]);
    }
  }
  return h;
}

/** FNV-1a hash for deterministic seeding. */
export function fnv1a(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) | 0;
  }
  return hash >>> 0;
}
