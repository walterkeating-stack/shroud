import { describe, test, expect } from "vitest";
import { SequenceEmbedder, generateNgrams } from "../src/detectors/sequence-embedder.js";

describe("SequenceEmbedder", () => {
  const embedder = new SequenceEmbedder(256);

  describe("generateNgrams", () => {
    test("generates unigrams, bigrams, trigrams", () => {
      const ngrams = generateNgrams(["read", "edit", "exec"]);
      // Unigrams: read, edit, exec
      expect(ngrams).toContain("read");
      expect(ngrams).toContain("edit");
      expect(ngrams).toContain("exec");
      // Bigrams: read→edit, edit→exec
      expect(ngrams).toContain("read\u2192edit");
      expect(ngrams).toContain("edit\u2192exec");
      // Trigrams: read→edit→exec
      expect(ngrams).toContain("read\u2192edit\u2192exec");
    });

    test("empty sequence returns empty", () => {
      expect(generateNgrams([])).toEqual([]);
    });

    test("single tool produces only unigram", () => {
      const ngrams = generateNgrams(["read"]);
      expect(ngrams).toEqual(["read"]);
    });

    test("two tools produce unigrams + one bigram", () => {
      const ngrams = generateNgrams(["read", "edit"]);
      expect(ngrams).toHaveLength(3); // read, edit, read→edit
    });
  });

  describe("embedding", () => {
    test("produces 256-dimensional vector", () => {
      const vec = embedder.embedSequence(["read", "edit", "exec"]);
      expect(vec).toBeInstanceOf(Float64Array);
      expect(vec.length).toBe(256);
    });

    test("empty sequence produces zero vector", () => {
      const vec = embedder.embedSequence([]);
      expect(vec.every(v => v === 0)).toBe(true);
    });

    test("L2 norm is approximately 1 for non-empty sequences", () => {
      const vec = embedder.embedSequence(["read", "edit", "exec"]);
      let norm = 0;
      for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
      expect(Math.sqrt(norm)).toBeCloseTo(1, 5);
    });

    test("identical sequences produce identical vectors", () => {
      const a = embedder.embedSequence(["read", "edit"]);
      const b = embedder.embedSequence(["read", "edit"]);
      expect(embedder.similarity(a, b)).toBeCloseTo(1, 5);
    });

    test("order matters — read→edit ≠ edit→read", () => {
      const a = embedder.embedSequence(["read", "edit"]);
      const b = embedder.embedSequence(["edit", "read"]);
      const sim = embedder.similarity(a, b);
      // Similar (share unigrams) but not identical (different bigrams)
      expect(sim).toBeLessThan(1);
      expect(sim).toBeGreaterThan(0);
    });

    test("completely different sequences have low similarity", () => {
      const a = embedder.embedSequence(["read", "edit", "exec"]);
      const b = embedder.embedSequence(["message", "web_fetch", "browser"]);
      const sim = embedder.similarity(a, b);
      expect(sim).toBeLessThan(0.5);
    });

    test("similar sequences have high similarity", () => {
      const a = embedder.embedSequence(["read", "edit", "exec", "read"]);
      const b = embedder.embedSequence(["read", "edit", "exec"]);
      const sim = embedder.similarity(a, b);
      expect(sim).toBeGreaterThan(0.7);
    });
  });

  describe("VectorProvider interface", () => {
    test("embed() accepts →-delimited string", () => {
      const fromString = embedder.embed("read\u2192edit\u2192exec");
      const fromArray = embedder.embedSequence(["read", "edit", "exec"]);
      expect(embedder.similarity(fromString, fromArray)).toBeCloseTo(1, 5);
    });

    test("dimensions property returns 256", () => {
      expect(embedder.dimensions).toBe(256);
    });
  });
});
