import { describe, test, expect } from "vitest";

import { Category } from "../src/types.js";
import { MappingEngine } from "../src/mapping.js";

describe("MappingEngine", () => {
  test("deterministic: same value + same salt produces same result", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake1 = engine.mapValue("john@example.com", Category.EMAIL);
    const fake2 = engine.mapValue("john@example.com", Category.EMAIL);
    expect(fake1).toBe(fake2);
  });

  test("different values produce different results", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake1 = engine.mapValue("alice@example.com", Category.EMAIL);
    const fake2 = engine.mapValue("bob@example.com", Category.EMAIL);
    expect(fake1).not.toBe(fake2);
  });

  test("different salts produce different results", () => {
    const engine1 = new MappingEngine("test-secret", "salt-a");
    const engine2 = new MappingEngine("test-secret", "salt-b");
    const fake1 = engine1.mapValue("john@example.com", Category.EMAIL);
    const fake2 = engine2.mapValue("john@example.com", Category.EMAIL);
    expect(fake1).not.toBe(fake2);
  });

  test("different keys produce different results", () => {
    const engine1 = new MappingEngine("key-a", "same-salt");
    const engine2 = new MappingEngine("key-b", "same-salt");
    const fake1 = engine1.mapValue("john@example.com", Category.EMAIL);
    const fake2 = engine2.mapValue("john@example.com", Category.EMAIL);
    expect(fake1).not.toBe(fake2);
  });

  test("auto-generated salt is random between instances", () => {
    const engine1 = new MappingEngine("test-secret");
    const engine2 = new MappingEngine("test-secret");
    expect(engine1.salt).not.toBe(engine2.salt);
  });

  test("mapValue returns valid email for EMAIL category", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("real@company.com", Category.EMAIL);
    expect(fake).toContain("@");
  });

  test("mapValue returns valid IP for IP_ADDRESS category", () => {
    const engine = new MappingEngine("test-secret", "fixed-salt");
    const fake = engine.mapValue("192.168.1.1", Category.IP_ADDRESS);
    const parts = fake.split(".");
    expect(parts.length).toBe(4);
    expect(parts[0]).toBe("100"); // CGNAT range
  });
});
