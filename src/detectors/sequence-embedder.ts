/**
 * N-gram sequence embedding for tool-call chains.
 *
 * Embeds ordered sequences of tool names (e.g. ["read","edit","exec"]) into
 * fixed-size dense vectors using uni/bi/trigram feature hashing. Unlike the
 * TF-IDF provider which treats tool descriptions as bags of words, this
 * preserves ordering: "read→edit" and "edit→read" hash to different buckets.
 *
 * Implements VectorProvider from drift-detector so it can be swapped in
 * anywhere the existing TF-IDF provider is used.
 *
 * Zero external dependencies — pure math on Node.js builtins.
 */

import type { VectorProvider } from "./drift-detector.js";

// ─── FNV-1a hash (shared implementation, same as drift-detector) ───

function fnv1a(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) | 0;
  }
  return hash >>> 0;
}

// ─── N-gram generation ───

/** Generate unigrams, bigrams, and trigrams from a tool name sequence. */
export function generateNgrams(tools: string[]): string[] {
  const ngrams: string[] = [];
  for (let i = 0; i < tools.length; i++) {
    // Unigram
    ngrams.push(tools[i]);
    // Bigram
    if (i + 1 < tools.length) {
      ngrams.push(`${tools[i]}\u2192${tools[i + 1]}`);
    }
    // Trigram
    if (i + 2 < tools.length) {
      ngrams.push(`${tools[i]}\u2192${tools[i + 1]}\u2192${tools[i + 2]}`);
    }
  }
  return ngrams;
}

// ─── Sequence embedder ───

/**
 * Embeds tool-call sequences into fixed-size dense vectors using n-gram
 * feature hashing with the sign trick (same approach as TfIdfProvider).
 *
 * The embed() method accepts a "→"-delimited string for VectorProvider
 * compatibility. Use embedSequence() for the typed array interface.
 */
export class SequenceEmbedder implements VectorProvider {
  readonly dimensions: number;

  constructor(dimensions = 256) {
    this.dimensions = dimensions;
  }

  /**
   * Embed a "→"-delimited sequence string.
   * VectorProvider interface — accepts "read→edit→exec".
   */
  embed(text: string): Float64Array {
    const tools = text.split("\u2192").map(t => t.trim()).filter(Boolean);
    return this.embedSequence(tools);
  }

  /** Embed an array of tool names preserving order via n-grams. */
  embedSequence(tools: string[]): Float64Array {
    const vec = new Float64Array(this.dimensions);
    if (tools.length === 0) return vec;

    const ngrams = generateNgrams(tools);

    // Count n-gram frequencies
    const freq = new Map<string, number>();
    for (const ng of ngrams) {
      freq.set(ng, (freq.get(ng) || 0) + 1);
    }

    // Feature hashing with sign trick
    for (const [ngram, count] of freq) {
      const bucket = fnv1a(ngram) % this.dimensions;
      const sign = (fnv1a(ngram + "\x00") & 1) === 0 ? 1 : -1;
      const weight = 1 + Math.log(count);
      vec[bucket] += sign * weight;
    }

    // L2 normalize
    let norm = 0;
    for (let i = 0; i < this.dimensions; i++) {
      norm += vec[i] * vec[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < this.dimensions; i++) {
        vec[i] /= norm;
      }
    }

    return vec;
  }

  /** Cosine similarity between two L2-normalized vectors. */
  similarity(a: Float64Array, b: Float64Array): number {
    let dot = 0;
    for (let i = 0; i < this.dimensions; i++) {
      dot += a[i] * b[i];
    }
    return Math.max(0, Math.min(1, dot));
  }
}
