import { describe, test, expect } from "vitest";

import { Category } from "../src/types.js";
import { MemoryStore } from "../src/store.js";

describe("MemoryStore", () => {
  test("put + getFake returns the fake value", () => {
    const store = new MemoryStore();
    store.put("real@email.com", "fake@email.com", Category.EMAIL);
    expect(store.getFake("real@email.com")).toBe("fake@email.com");
  });

  test("put + getReal returns the real value", () => {
    const store = new MemoryStore();
    store.put("real@email.com", "fake@email.com", Category.EMAIL);
    expect(store.getReal("fake@email.com")).toBe("real@email.com");
  });

  test("unknown value returns undefined", () => {
    const store = new MemoryStore();
    expect(store.getFake("nonexistent")).toBeUndefined();
    expect(store.getReal("nonexistent")).toBeUndefined();
  });

  test("allMappings returns all entries", () => {
    const store = new MemoryStore();
    store.put("a", "x", Category.EMAIL);
    store.put("b", "y", Category.IP_ADDRESS);
    store.put("c", "z", Category.PHONE);
    const mappings = store.allMappings();
    expect(mappings.size).toBe(3);
    expect(mappings.get("a")).toBe("x");
    expect(mappings.get("b")).toBe("y");
    expect(mappings.get("c")).toBe("z");
  });

  test("clear removes everything", () => {
    const store = new MemoryStore();
    store.put("real", "fake", Category.EMAIL);
    store.put("real2", "fake2", Category.IP_ADDRESS);
    expect(store.allMappings().size).toBe(2);
    store.clear();
    expect(store.allMappings().size).toBe(0);
    expect(store.getFake("real")).toBeUndefined();
    expect(store.getReal("fake")).toBeUndefined();
  });

  test("multiple entries work correctly", () => {
    const store = new MemoryStore();
    store.put("alice@test.com", "contact@nexus.dev", Category.EMAIL);
    store.put("10.0.0.1", "100.64.0.1", Category.IP_ADDRESS);
    expect(store.getFake("alice@test.com")).toBe("contact@nexus.dev");
    expect(store.getFake("10.0.0.1")).toBe("100.64.0.1");
    expect(store.getReal("contact@nexus.dev")).toBe("alice@test.com");
    expect(store.getReal("100.64.0.1")).toBe("10.0.0.1");
  });
});
