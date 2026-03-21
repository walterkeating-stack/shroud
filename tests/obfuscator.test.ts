import { describe, test, expect } from "vitest";

import { ShroudConfig, Category, DetectedEntity } from "../src/types.js";
import { Obfuscator, resolveOverlaps } from "../src/obfuscator.js";

const testConfig: ShroudConfig = {
  secretKey: "test-secret-key-1234567890abcdef",
  persistentSalt: "fixed-test-salt",
  minConfidence: 0,
  allowlist: [],
  denylist: [],
  canaryEnabled: false,
  canaryPrefix: "SHROUD-CANARY",
  auditEnabled: false,
  logMappings: false,
  customPatterns: [],
};

function makeObfuscator(overrides?: Partial<ShroudConfig>): Obfuscator {
  return new Obfuscator({ ...testConfig, ...overrides });
}

describe("Obfuscator", () => {
  test("obfuscate email: real email not in output", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Contact john@acme.com for info");
    expect(result.obfuscated).not.toContain("john@acme.com");
    expect(result.obfuscated).toContain("@"); // Replaced with fake email
    expect(result.mappingsUsed).toHaveProperty("john@acme.com");
  });

  test("obfuscate IP: real IP not in output, fake in CGNAT range", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("Server at 192.168.1.100");
    expect(result.obfuscated).not.toContain("192.168.1.100");
    expect(result.obfuscated).toContain("100."); // CGNAT range
  });

  test("obfuscate API key: real key not in output", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate(
      "Use key SHROUD_TEST_API_KEY",
    );
    expect(result.obfuscated).not.toContain(
      "SHROUD_TEST_API_KEY",
    );
  });

  test("deobfuscate roundtrip: obfuscate then deobfuscate returns original", () => {
    const obf = makeObfuscator();
    const original = "Send to john@acme.com from 192.168.1.100";
    const result = obf.obfuscate(original);
    const restored = obf.deobfuscate(result.obfuscated);
    expect(restored).toBe(original);
  });

  test("deterministic: same text + same config produces same output", () => {
    const obf = makeObfuscator();
    const r1 = obf.obfuscate("Contact john@acme.com");
    const r2 = obf.obfuscate("Also reach john@acme.com here");
    // Same email should map to same fake
    expect(r1.mappingsUsed["john@acme.com"]).toBe(
      r2.mappingsUsed["john@acme.com"],
    );
  });

  test("allowlist: listed values not obfuscated", () => {
    const obf = makeObfuscator({ allowlist: ["10.0.0.1"] });
    const result = obf.obfuscate("Server at 10.0.0.1");
    expect(result.obfuscated).toContain("10.0.0.1");
  });

  test("denylist: listed values always obfuscated", () => {
    const obf = makeObfuscator({ denylist: ["SecretProject"] });
    const result = obf.obfuscate("Working on SecretProject today");
    expect(result.obfuscated).not.toContain("SecretProject");
  });

  test("confidence filtering works", () => {
    // Set a high minConfidence that should filter out lower confidence detections
    const obf = makeObfuscator({ minConfidence: 0.99 });
    // Phone detection has confidence 0.8, should be filtered
    const result = obf.obfuscate("Call (555) 123-4567");
    // The phone might still be there since confidence is below threshold
    // At 0.99 threshold, only confidence >= 0.99 entities pass
    expect(result.entities.every((e) => e.confidence >= 0.99)).toBe(true);
  });

  test("empty text returns empty", () => {
    const obf = makeObfuscator();
    const result = obf.obfuscate("");
    expect(result.obfuscated).toBe("");
    expect(Object.keys(result.mappingsUsed).length).toBe(0);
  });

  test("text with no PII returns unchanged", () => {
    const obf = makeObfuscator();
    const text = "The quick brown fox jumps over the lazy dog";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).toBe(text);
    expect(Object.keys(result.mappingsUsed).length).toBe(0);
  });

  test("multiple entities in one text all obfuscated", () => {
    const obf = makeObfuscator();
    const text =
      "Email john@acme.com, server 10.20.30.40, key SHROUD_TEST_API_KEY";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).not.toContain("john@acme.com");
    expect(result.obfuscated).not.toContain("10.20.30.40");
    expect(Object.keys(result.mappingsUsed).length).toBeGreaterThanOrEqual(2);
  });

  test("complex text roundtrip", () => {
    const obf = makeObfuscator();
    const text =
      "Hi, this is John from Acme Corp. " +
      "Please email me at john.doe@acme-corp.com or call (555) 123-4567. " +
      "Our server is at 172.16.0.50 and the docs are at " +
      "https://internal.acme-corp.com/docs. " +
      "My SSN is 123-45-6789.";
    const result = obf.obfuscate(text);
    expect(result.obfuscated).not.toContain("john.doe@acme-corp.com");
    expect(result.obfuscated).not.toContain("172.16.0.50");
    expect(result.obfuscated).not.toContain("123-45-6789");
    const restored = obf.deobfuscate(result.obfuscated);
    expect(restored).toContain("john.doe@acme-corp.com");
    expect(restored).toContain("172.16.0.50");
  });
});

describe("resolveOverlaps", () => {
  test("keeps higher confidence, removes overlapping", () => {
    const entities: DetectedEntity[] = [
      {
        value: "123-45-6789",
        start: 0,
        end: 11,
        category: Category.SSN,
        confidence: 0.9,
        detector: "regex",
      },
      {
        value: "123-45",
        start: 0,
        end: 6,
        category: Category.PHONE,
        confidence: 0.5,
        detector: "regex",
      },
    ];
    // Sort as the obfuscator would: by start, then higher confidence first
    entities.sort(
      (a, b) => a.start - b.start || b.confidence - a.confidence,
    );
    const resolved = resolveOverlaps(entities);
    expect(resolved.length).toBe(1);
    expect(resolved[0].category).toBe(Category.SSN);
  });

  test("non-overlapping entities are all kept", () => {
    const entities: DetectedEntity[] = [
      {
        value: "john@test.com",
        start: 0,
        end: 13,
        category: Category.EMAIL,
        confidence: 0.95,
        detector: "regex",
      },
      {
        value: "10.0.0.1",
        start: 20,
        end: 28,
        category: Category.IP_ADDRESS,
        confidence: 0.95,
        detector: "regex",
      },
    ];
    const resolved = resolveOverlaps(entities);
    expect(resolved.length).toBe(2);
  });

  test("empty input returns empty", () => {
    expect(resolveOverlaps([])).toEqual([]);
  });
});
