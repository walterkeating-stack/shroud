import { describe, test, expect } from "vitest";

import { Category, DetectedEntity } from "../src/types.js";
import { AuditLogger } from "../src/audit.js";

function makeEntities(): DetectedEntity[] {
  return [
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
    {
      value: "10.0.0.2",
      start: 30,
      end: 38,
      category: Category.IP_ADDRESS,
      confidence: 0.95,
      detector: "regex",
    },
  ];
}

describe("AuditLogger - obfuscation", () => {
  test("logObfuscation records an entry", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    const stats = logger.getStats() as any;
    expect(stats.totalObfuscationEvents).toBe(1);
    expect(stats.totalEntitiesScrubbed).toBe(3);
  });

  test("getStats returns correct counts", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    logger.logObfuscation(makeEntities(), 200);
    const stats = logger.getStats() as any;
    expect(stats.totalEvents).toBe(2);
    expect(stats.totalObfuscationEvents).toBe(2);
    expect(stats.totalEntitiesScrubbed).toBe(6);
    expect(stats.byCategory[Category.EMAIL]).toBe(2);
    expect(stats.byCategory[Category.IP_ADDRESS]).toBe(4);
  });
});

describe("AuditLogger - deobfuscation", () => {
  test("logDeobfuscation records an entry", () => {
    const logger = new AuditLogger("test-secret");
    logger.logDeobfuscation(5, "req-deob-1", 3.21);
    const stats = logger.getStats() as any;
    expect(stats.totalDeobfuscationEvents).toBe(1);
    expect(stats.totalReplacementsRestored).toBe(5);
  });

  test("logDeobfuscation skips zero replacements", () => {
    const logger = new AuditLogger("test-secret");
    logger.logDeobfuscation(0);
    const stats = logger.getStats() as any;
    expect(stats.totalDeobfuscationEvents).toBe(0);
  });
});

describe("AuditLogger - chain integrity", () => {
  test("verifyChain returns valid for untampered log", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    logger.logObfuscation(makeEntities(), 200);
    logger.logObfuscation(makeEntities(), 300);
    const { valid, entriesChecked } = logger.verifyChain();
    expect(valid).toBe(true);
    expect(entriesChecked).toBe(3);
  });

  test("mixed obfuscation/deobfuscation chain is valid", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    logger.logDeobfuscation(3, "r1");
    logger.logObfuscation(makeEntities(), 200);
    logger.logDeobfuscation(2, "r2");
    const { valid, entriesChecked } = logger.verifyChain();
    expect(valid).toBe(true);
    expect(entriesChecked).toBe(4);
  });

  test("chain hash changes if entry is tampered", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    logger.logObfuscation(makeEntities(), 200);

    // Verify it's valid first
    expect(logger.verifyChain().valid).toBe(true);

    // Tamper with internal entries via reflection
    // Access the private _entries array
    const entries = (logger as any)._entries;
    entries[0].categories[Category.EMAIL] = 999;

    const { valid } = logger.verifyChain();
    expect(valid).toBe(false);
  });
});

describe("AuditLogger - ring buffer", () => {
  test("evicts oldest entries when full", () => {
    const logger = new AuditLogger("test-secret", 5);
    for (let i = 0; i < 8; i++) {
      logger.logObfuscation(makeEntities(), 100 + i);
    }
    // The internal _entries array should only have 5 entries
    const entries = (logger as any)._entries;
    expect(entries.length).toBe(5);
    // Stats should still count all 8
    const stats = logger.getStats() as any;
    expect(stats.totalObfuscationEvents).toBe(8);
    expect(stats.totalEntitiesScrubbed).toBe(24); // 8 * 3
  });
});

describe("AuditLogger - deobfuscation stats", () => {
  test("mixed stats are correct", () => {
    const logger = new AuditLogger("test-secret");
    logger.logObfuscation(makeEntities(), 100);
    logger.logDeobfuscation(3);
    logger.logDeobfuscation(2);
    const stats = logger.getStats() as any;
    expect(stats.totalObfuscationEvents).toBe(1);
    expect(stats.totalDeobfuscationEvents).toBe(2);
    expect(stats.totalEvents).toBe(3);
    expect(stats.totalReplacementsRestored).toBe(5);
  });
});
