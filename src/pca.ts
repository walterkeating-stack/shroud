/**
 * PCA dimensionality reduction — projects high-dimensional vectors to 3D
 * for dashboard visualization.
 *
 * Uses power iteration to find the top-k principal components of the
 * covariance matrix. For N<1000 vectors at D=256 dimensions with k=3
 * components and ~50 iterations, this runs in milliseconds.
 *
 * Zero external dependencies — pure Float64Array math.
 */

// ─── FNV-1a for deterministic seeding ───

function fnv1a(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) | 0;
  }
  return hash >>> 0;
}

/** Simple seeded PRNG (xorshift32) for reproducible initial vectors. */
function xorshift32(seed: number): () => number {
  let state = seed | 1; // Ensure non-zero
  return () => {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return (state >>> 0) / 0xffffffff;
  };
}

// ─── PCA via power iteration ───

export interface PcaResult {
  /** Project a D-dimensional vector to k dimensions. */
  project(vec: Float64Array): number[];
  /** The k principal component vectors (each D-dimensional). */
  components: Float64Array[];
  /** Explained variance per component. */
  variance: number[];
}

/**
 * Compute PCA on a set of vectors and return a projection function.
 *
 * @param vectors - Array of D-dimensional vectors (all same length)
 * @param k - Number of principal components (default: 3)
 * @param iterations - Power iteration count (default: 50)
 * @param seed - Optional seed for reproducible results
 */
export function pca(
  vectors: Float64Array[],
  k = 3,
  iterations = 50,
  seed?: string,
): PcaResult {
  if (vectors.length === 0) {
    return {
      project: () => new Array(k).fill(0),
      components: [],
      variance: [],
    };
  }

  const n = vectors.length;
  const d = vectors[0].length;

  // 1. Compute mean
  const mean = new Float64Array(d);
  for (const vec of vectors) {
    for (let i = 0; i < d; i++) mean[i] += vec[i];
  }
  for (let i = 0; i < d; i++) mean[i] /= n;

  // 2. Center the data (copy to avoid mutating input)
  const centered: Float64Array[] = vectors.map(vec => {
    const c = new Float64Array(d);
    for (let i = 0; i < d; i++) c[i] = vec[i] - mean[i];
    return c;
  });

  // 3. Power iteration for top-k eigenvectors
  const rng = xorshift32(seed ? fnv1a(seed) : fnv1a(`pca-${n}-${d}`));
  const components: Float64Array[] = [];
  const variances: number[] = [];

  for (let comp = 0; comp < k; comp++) {
    // Initialize random unit vector
    const v = new Float64Array(d);
    for (let i = 0; i < d; i++) v[i] = rng() - 0.5;
    l2Normalize(v);

    // Power iteration: v = (X^T * X * v) / ||X^T * X * v||
    for (let iter = 0; iter < iterations; iter++) {
      // w = X * v (project data onto v: n-dimensional)
      const w = new Float64Array(n);
      for (let i = 0; i < n; i++) {
        let dot = 0;
        for (let j = 0; j < d; j++) dot += centered[i][j] * v[j];
        w[i] = dot;
      }

      // v_new = X^T * w (back-project: d-dimensional)
      const vNew = new Float64Array(d);
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < d; j++) vNew[j] += centered[i][j] * w[i];
      }

      // Normalize
      l2Normalize(vNew);
      for (let i = 0; i < d; i++) v[i] = vNew[i];
    }

    // Compute variance along this component
    let eigenvalue = 0;
    for (let i = 0; i < n; i++) {
      let dot = 0;
      for (let j = 0; j < d; j++) dot += centered[i][j] * v[j];
      eigenvalue += dot * dot;
    }
    eigenvalue /= n;
    variances.push(eigenvalue);

    components.push(new Float64Array(v));

    // 4. Deflate: remove this component from the data
    for (let i = 0; i < n; i++) {
      let dot = 0;
      for (let j = 0; j < d; j++) dot += centered[i][j] * v[j];
      for (let j = 0; j < d; j++) centered[i][j] -= dot * v[j];
    }
  }

  // Total variance for explained ratio
  const totalVariance = variances.reduce((a, b) => a + b, 0) || 1;

  return {
    project(vec: Float64Array): number[] {
      const result: number[] = [];
      for (const comp of components) {
        let dot = 0;
        for (let i = 0; i < d; i++) dot += (vec[i] - mean[i]) * comp[i];
        result.push(dot);
      }
      return result;
    },
    components,
    variance: variances.map(v => v / totalVariance),
  };
}

/** L2-normalize a vector in place. */
function l2Normalize(v: Float64Array): void {
  let norm = 0;
  for (let i = 0; i < v.length; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm);
  if (norm > 0) {
    for (let i = 0; i < v.length; i++) v[i] /= norm;
  }
}
