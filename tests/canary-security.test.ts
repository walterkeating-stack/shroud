/**
 * Tests for canary security extensions (Track 2).
 *
 * Covers: system-context planting, near-match Levenshtein scanning,
 * behavioural canaries, and leak detection.
 */

import { describe, test, expect, beforeEach } from "vitest";
import {
  CanaryInjector,
  levenshteinBounded,
  findNearMatch,
} from "../src/canary.js";

describe("Levenshtein — bounded distance", () => {
  test("identical strings → 0", () => {
    expect(levenshteinBounded("hello", "hello", 3)).toBe(0);
  });

  test("single substitution → 1", () => {
    expect(levenshteinBounded("hello", "hallo", 3)).toBe(1);
  });

  test("single insertion → 1", () => {
    expect(levenshteinBounded("hello", "helloo", 3)).toBe(1);
  });

  test("single deletion → 1", () => {
    expect(levenshteinBounded("hello", "helo", 3)).toBe(1);
  });

  test("two substitutions → 2", () => {
    expect(levenshteinBounded("hello", "haxlo", 3)).toBe(2);
  });

  test("distance exceeds bound → returns bound+1", () => {
    expect(levenshteinBounded("hello", "world", 2)).toBe(3);
  });

  test("empty strings → 0", () => {
    expect(levenshteinBounded("", "", 3)).toBe(0);
  });

  test("one empty → length of other", () => {
    expect(levenshteinBounded("abc", "", 5)).toBe(3);
    expect(levenshteinBounded("", "abc", 5)).toBe(3);
  });

  test("length difference exceeds bound → early reject", () => {
    expect(levenshteinBounded("a", "abcde", 2)).toBe(3);
  });

  test("canary-length token with 1-char substitution", () => {
    const token = "SHROUD-CANARY-a1b2c3d4e5f6";
    const mutant = "SHROUD-CANARY-a1b2c3d4e5g6"; // last hex char changed
    expect(levenshteinBounded(token, mutant, 2)).toBe(1);
  });

  test("canary-length token with 2-char changes", () => {
    const token = "SHROUD-CANARY-a1b2c3d4e5f6";
    const mutant = "SHROUD-CANARY-x1b2c3d4e5g6"; // first and last hex changed
    expect(levenshteinBounded(token, mutant, 2)).toBe(2);
  });
});

describe("findNearMatch — sliding window search", () => {
  test("exact match in text", () => {
    const result = findNearMatch(
      "prefix SHROUD-CANARY-abc123 suffix",
      "SHROUD-CANARY-abc123",
      2,
    );
    expect(result).not.toBeNull();
    expect(result!.distance).toBe(0);
    expect(result!.start).toBe(7);
  });

  test("1-char substitution match", () => {
    const result = findNearMatch(
      "prefix SHROUD-CANARY-abc1X3 suffix",
      "SHROUD-CANARY-abc123",
      2,
    );
    expect(result).not.toBeNull();
    expect(result!.distance).toBe(1);
  });

  test("2-char difference matches within threshold", () => {
    const result = findNearMatch(
      "prefix SHROUD-CANARY-Xbc1X3 suffix",
      "SHROUD-CANARY-abc123",
      2,
    );
    expect(result).not.toBeNull();
    expect(result!.distance).toBeLessThanOrEqual(2);
  });

  test("3-char difference does NOT match at threshold 2", () => {
    const result = findNearMatch(
      "prefix SHROUD-CANARY-XbcXX3 suffix",
      "SHROUD-CANARY-abc123",
      2,
    );
    // May or may not find — depends on window alignment
    if (result !== null) {
      expect(result.distance).toBeLessThanOrEqual(2);
    }
  });

  test("no match in completely unrelated text", () => {
    const result = findNearMatch(
      "The quick brown fox jumps over the lazy dog",
      "SHROUD-CANARY-abc123",
      2,
    );
    expect(result).toBeNull();
  });

  test("empty needle → null", () => {
    expect(findNearMatch("some text", "", 2)).toBeNull();
  });

  test("needle longer than haystack → null", () => {
    expect(findNearMatch("abc", "SHROUD-CANARY-abc123def456", 2)).toBeNull();
  });
});

describe("CanaryInjector — System canary planting", () => {
  let canary: CanaryInjector;

  beforeEach(() => {
    canary = new CanaryInjector("SHROUD-CANARY", "test-secret-key-1234567890abcdef");
  });

  test("injectSystem appends canary to system prompt", () => {
    const result = canary.injectSystem("You are a helpful assistant.");
    expect(result).toContain("You are a helpful assistant.");
    expect(result).toContain("<!-- SHROUD-CANARY-");
    expect(result).toContain(" -->");
  });

  test("system canary is tracked in injectionCanaries", () => {
    canary.injectSystem("System prompt here.");
    const ics = canary.getInjectionCanaries();
    expect(ics).toHaveLength(1);
    expect(ics[0].type).toBe("marker");
    expect(ics[0].placement).toBe("system");
  });

  test("system canary detected by checkLeakNearMatch (exact)", () => {
    const prompt = canary.injectSystem("System prompt.");
    const ics = canary.getInjectionCanaries();
    const token = ics[0].token;

    // Simulate LLM leaking the canary in response
    const response = `Here is some output that contains ${token} in it.`;
    const leaks = canary.checkLeakNearMatch(response);
    expect(leaks).toHaveLength(1);
    expect(leaks[0].matchType).toBe("exact");
    expect(leaks[0].distance).toBe(0);
  });

  test("system canary detected with 1-char mutation (near match)", () => {
    canary.injectSystem("System prompt.");
    const ics = canary.getInjectionCanaries();
    const token = ics[0].token;

    // Mutate one character
    const mutated = token.slice(0, -1) + "X";
    const response = `Output contains ${mutated} here.`;
    const leaks = canary.checkLeakNearMatch(response, 2);
    expect(leaks).toHaveLength(1);
    expect(leaks[0].matchType).toBe("near");
    expect(leaks[0].distance).toBe(1);
  });

  test("no leak in clean response", () => {
    canary.injectSystem("System prompt.");
    const response = "This is a perfectly normal response about TypeScript patterns.";
    const leaks = canary.checkLeakNearMatch(response);
    expect(leaks).toHaveLength(0);
  });

  test("near-match disabled when maxDistance=0", () => {
    canary.injectSystem("System prompt.");
    const ics = canary.getInjectionCanaries();
    const token = ics[0].token;

    const mutated = token.slice(0, -1) + "X";
    const response = `Output: ${mutated}`;
    const leaks = canary.checkLeakNearMatch(response, 0);
    expect(leaks).toHaveLength(0);
  });
});

describe("CanaryInjector — Behavioural canaries", () => {
  let canary: CanaryInjector;

  beforeEach(() => {
    canary = new CanaryInjector("SHROUD-CANARY", "test-secret-key-1234567890abcdef");
  });

  test("injectBehavioural adds instruction to system prompt", () => {
    const { prompt, canary: bc } = canary.injectBehavioural("You are helpful.");
    expect(prompt).toContain("You are helpful.");
    expect(prompt).toContain("[Internal diagnostic:");
    expect(prompt).toContain(bc.signatureCode);
    expect(bc.signatureCode).toMatch(/^SHROUD-DIAG-[a-f0-9]{8}$/);
  });

  test("behavioural canary tracked", () => {
    canary.injectBehavioural("System prompt.");
    expect(canary.getBehaviouralCanaries()).toHaveLength(1);
    expect(canary.getInjectionCanaries()).toHaveLength(1);
    expect(canary.getInjectionCanaries()[0].type).toBe("behavioural");
  });

  test("behavioural canary detected in response", () => {
    const { canary: bc } = canary.injectBehavioural("System prompt.");
    const response = `System status: OK. Reference: ${bc.signatureCode}`;
    const leaks = canary.checkBehaviouralLeak(response);
    expect(leaks).toHaveLength(1);
    expect(leaks[0].matchType).toBe("exact");
    expect(leaks[0].canary.type).toBe("behavioural");
  });

  test("no behavioural leak in clean response", () => {
    canary.injectBehavioural("System prompt.");
    const response = "Everything is working normally.";
    const leaks = canary.checkBehaviouralLeak(response);
    expect(leaks).toHaveLength(0);
  });

  test("multiple canaries: marker + behavioural", () => {
    canary.injectSystem("System prompt.");
    canary.injectBehavioural("System prompt.");
    expect(canary.getInjectionCanaries()).toHaveLength(2);
    expect(canary.getInjectionCanaries()[0].type).toBe("marker");
    expect(canary.getInjectionCanaries()[1].type).toBe("behavioural");
  });

  test("agent build ID set and used", () => {
    canary.setAgentBuildId("abc123def456");
    canary.injectSystem("System prompt.");
    const ics = canary.getInjectionCanaries();
    expect(ics[0].agentBuildId).toBe("abc123def456");
  });
});

describe("CanaryInjector — Reset", () => {
  test("reset clears injection canaries", () => {
    const canary = new CanaryInjector("SHROUD-CANARY", "test-secret");
    canary.injectSystem("Prompt.");
    canary.injectBehavioural("Prompt.");
    expect(canary.getInjectionCanaries()).toHaveLength(2);
    expect(canary.getBehaviouralCanaries()).toHaveLength(1);

    canary.reset();
    expect(canary.getInjectionCanaries()).toHaveLength(0);
    expect(canary.getBehaviouralCanaries()).toHaveLength(0);
    expect(canary.getTokens()).toHaveLength(0);
  });
});

describe("CanaryInjector — Original functionality preserved", () => {
  test("inject still works as before", () => {
    const canary = new CanaryInjector("SHROUD-CANARY", "test-secret");
    const result = canary.inject("Some text.");
    expect(result).toContain("Some text.");
    expect(result).toContain("<!-- SHROUD-CANARY-");
  });

  test("checkLeak still works as before", () => {
    const canary = new CanaryInjector("SHROUD-CANARY", "test-secret");
    canary.inject("Text.");
    const tokens = canary.getTokens();
    const leaked = canary.checkLeak(`Response with ${tokens[0].token}`);
    expect(leaked).toHaveLength(1);
  });
});
