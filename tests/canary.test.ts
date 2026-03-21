import { describe, test, expect } from "vitest";

import { CanaryInjector } from "../src/canary.js";

describe("CanaryInjector", () => {
  test("inject adds canary comment to text", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    const result = inj.inject("Hello world");
    expect(result).toContain("SHROUD-CANARY-");
    expect(result).toContain("Hello world");
    expect(result).toContain("<!--");
    expect(result).toContain("-->");
  });

  test("multiple injects produce different tokens", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("msg1");
    inj.inject("msg2");
    const tokens = inj.getTokens();
    expect(tokens.length).toBe(2);
    expect(tokens[0].token).not.toBe(tokens[1].token);
  });

  test("checkLeak finds injected tokens", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("Hello");
    const token = inj.getTokens()[0].token;
    const leaked = inj.checkLeak(`Some text with ${token} in it`);
    expect(leaked.length).toBe(1);
    expect(leaked[0].token).toBe(token);
  });

  test("checkLeak returns empty for unknown text", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("Hello");
    const leaked = inj.checkLeak("Some unrelated text");
    expect(leaked.length).toBe(0);
  });

  test("reset clears tokens and generates new session ID", async () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("msg");
    const oldSession = inj.sessionId;
    expect(inj.getTokens().length).toBe(1);

    // Wait 2ms so Date.now() changes (used in session ID hash)
    await new Promise((resolve) => setTimeout(resolve, 2));

    inj.reset();
    expect(inj.getTokens().length).toBe(0);
    // Session ID is based on Date.now(), so it should differ after the delay
    expect(inj.sessionId).not.toBe(oldSession);
  });

  test("getTokens returns all injected tokens", () => {
    const inj = new CanaryInjector("SHROUD-CANARY", "test-secret");
    inj.inject("first");
    inj.inject("second");
    inj.inject("third");
    const tokens = inj.getTokens();
    expect(tokens.length).toBe(3);
    expect(tokens[0].messageIndex).toBe(1);
    expect(tokens[1].messageIndex).toBe(2);
    expect(tokens[2].messageIndex).toBe(3);
  });
});
