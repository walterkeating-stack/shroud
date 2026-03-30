import { describe, test, expect } from "vitest";

import { CanaryInjector, encodeZeroWidth, decodeZeroWidth } from "../src/canary.js";

describe("Zero-width encoding", () => {
  test("encode then decode roundtrips", () => {
    const original = "SHROUD-CANARY-abc123";
    const encoded = encodeZeroWidth(original);
    expect(encoded).not.toContain(original); // invisible
    expect(encoded.length).toBeGreaterThan(0);
    const decoded = decodeZeroWidth(encoded);
    expect(decoded).toBe(original);
  });

  test("encoded text is invisible (only zero-width chars)", () => {
    const encoded = encodeZeroWidth("test");
    // Should only contain zero-width chars and delimiters
    for (const ch of encoded) {
      expect(["\u200B", "\u200C", "\u200D"].includes(ch)).toBe(true);
    }
  });

  test("decode extracts from mixed text", () => {
    const encoded = encodeZeroWidth("CANARY-123");
    const mixed = "Hello world" + encoded + " more text";
    const decoded = decodeZeroWidth(mixed);
    expect(decoded).toBe("CANARY-123");
  });
});

describe("CanaryInjector", () => {
  test("inject adds invisible canary to text", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    const result = inj.inject("Hello world");
    // Original text preserved
    expect(result).toContain("Hello world");
    // Canary is NOT visible as plaintext
    expect(result).not.toContain("SHROUD-CANARY-");
    expect(result).not.toContain("<!--");
    // But it's there as zero-width chars
    expect(result.length).toBeGreaterThan("Hello world".length);
  });

  test("multiple injects produce different tokens", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("msg1");
    inj.inject("msg2");
    const tokens = inj.getTokens();
    expect(tokens.length).toBe(2);
    expect(tokens[0].token).not.toBe(tokens[1].token);
  });

  test("checkLeak finds token in plaintext", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("Hello");
    const token = inj.getTokens()[0].token;
    const leaked = inj.checkLeak(`Some text with ${token} in it`);
    expect(leaked.length).toBe(1);
  });

  test("checkLeak finds token in zero-width encoded form", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    const result = inj.inject("Hello");
    // The encoded canary from inject should be detectable
    const token = inj.getTokens()[0].token;
    const encoded = encodeZeroWidth(token);
    const leaked = inj.checkLeak(`Response text${encoded}`);
    expect(leaked.length).toBe(1);
  });

  test("checkLeak returns empty for unknown text", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("Hello");
    const leaked = inj.checkLeak("Some unrelated text");
    expect(leaked.length).toBe(0);
  });

  test("reset clears tokens", async () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("msg");
    expect(inj.getTokens().length).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 2));
    inj.reset();
    expect(inj.getTokens().length).toBe(0);
  });
});
