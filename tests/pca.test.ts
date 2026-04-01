import { describe, test, expect } from "vitest";
import { pca } from "../src/pca.js";

describe("PCA", () => {
  test("empty input returns zero projection", () => {
    const result = pca([], 3);
    expect(result.project(new Float64Array(10))).toEqual([0, 0, 0]);
    expect(result.components).toHaveLength(0);
  });

  test("projects to k dimensions", () => {
    // Create simple data with clear structure
    const vectors = [];
    for (let i = 0; i < 20; i++) {
      const v = new Float64Array(10);
      v[0] = i * 0.1;      // Strong first component
      v[1] = i * 0.05;     // Weaker second component
      v[2] = Math.random() * 0.01; // Noise
      vectors.push(v);
    }

    const result = pca(vectors, 3);
    expect(result.components).toHaveLength(3);
    expect(result.variance).toHaveLength(3);

    // First component should explain the most variance
    expect(result.variance[0]).toBeGreaterThan(result.variance[1]);
  });

  test("projection preserves relative distances", () => {
    const vectors: Float64Array[] = [];
    // Two clusters
    for (let i = 0; i < 10; i++) {
      const v = new Float64Array(50);
      v[0] = 5 + Math.random() * 0.1;
      v[1] = 5 + Math.random() * 0.1;
      vectors.push(v);
    }
    for (let i = 0; i < 10; i++) {
      const v = new Float64Array(50);
      v[0] = -5 + Math.random() * 0.1;
      v[1] = -5 + Math.random() * 0.1;
      vectors.push(v);
    }

    const result = pca(vectors, 3, 50, "test-seed");

    // Points in same cluster should be close in projection
    const p0 = result.project(vectors[0]);
    const p1 = result.project(vectors[1]);
    const p10 = result.project(vectors[10]);

    const dist01 = Math.sqrt(p0.reduce((s, v, i) => s + (v - p1[i]) ** 2, 0));
    const dist010 = Math.sqrt(p0.reduce((s, v, i) => s + (v - p10[i]) ** 2, 0));

    // Within-cluster distance should be much less than between-cluster distance
    expect(dist01).toBeLessThan(dist010);
  });

  test("variance explained sums to approximately 1", () => {
    const vectors: Float64Array[] = [];
    for (let i = 0; i < 30; i++) {
      const v = new Float64Array(20);
      for (let j = 0; j < 20; j++) v[j] = Math.random();
      vectors.push(v);
    }

    const result = pca(vectors, 3);
    const total = result.variance.reduce((a, b) => a + b, 0);
    // With 3 components out of 20, shouldn't capture all variance
    expect(total).toBeLessThanOrEqual(1.01);
    expect(total).toBeGreaterThan(0);
  });

  test("deterministic with same seed", () => {
    const vectors: Float64Array[] = [];
    for (let i = 0; i < 10; i++) {
      const v = new Float64Array(10);
      for (let j = 0; j < 10; j++) v[j] = i * 0.1 + j * 0.01;
      vectors.push(v);
    }

    const r1 = pca(vectors, 3, 50, "my-seed");
    const r2 = pca(vectors, 3, 50, "my-seed");

    const p1 = r1.project(vectors[0]);
    const p2 = r2.project(vectors[0]);
    expect(p1[0]).toBeCloseTo(p2[0], 10);
    expect(p1[1]).toBeCloseTo(p2[1], 10);
    expect(p1[2]).toBeCloseTo(p2[2], 10);
  });

  test("single vector projects to origin", () => {
    const v = new Float64Array(10);
    v[0] = 5; v[1] = 3;
    const result = pca([v], 3);
    const p = result.project(v);
    // Single point centered = at origin
    expect(p[0]).toBeCloseTo(0, 5);
  });
});
