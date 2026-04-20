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

// ---------------------------------------------------------------------------
// QW10: LRU store eviction
// ---------------------------------------------------------------------------

describe("LRU eviction (QW10)", () => {
  test("evicts oldest entry when maxSize exceeded", () => {
    const store = new MemoryStore(2);
    store.put("a", "x", Category.EMAIL);
    store.put("b", "y", Category.IP_ADDRESS);
    expect(store.size()).toBe(2);
    // Adding third should evict "a"
    store.put("c", "z", Category.PHONE);
    expect(store.size()).toBe(2);
    expect(store.getFake("a")).toBeUndefined();
    expect(store.getReal("x")).toBeUndefined();
    expect(store.getFake("b")).toBe("y");
    expect(store.getFake("c")).toBe("z");
  });

  test("updating existing entry does not trigger eviction", () => {
    const store = new MemoryStore(2);
    store.put("a", "x", Category.EMAIL);
    store.put("b", "y", Category.IP_ADDRESS);
    // Update "a" with new fake — should NOT evict
    store.put("a", "x2", Category.EMAIL);
    expect(store.size()).toBe(2);
    expect(store.getFake("a")).toBe("x2");
    expect(store.getFake("b")).toBe("y");
  });

  test("maxSize=0 means unlimited", () => {
    const store = new MemoryStore(0);
    for (let i = 0; i < 100; i++) {
      store.put(`r${i}`, `f${i}`, Category.EMAIL);
    }
    expect(store.size()).toBe(100);
  });

  test("clear resets LRU tracking", () => {
    const store = new MemoryStore(2);
    store.put("a", "x", Category.EMAIL);
    store.put("b", "y", Category.IP_ADDRESS);
    store.clear();
    expect(store.size()).toBe(0);
    // Can add again without hitting limit from old entries
    store.put("c", "z", Category.PHONE);
    store.put("d", "w", Category.SSN);
    expect(store.size()).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Collision handling: two real values mapped to the same fake
// ---------------------------------------------------------------------------

describe("collision eviction", () => {
  test("collision evicts the old real value to keep store consistent", () => {
    const store = new MemoryStore();
    store.put("Morgan", "PREVIEW", Category.PERSON_NAME);
    store.put("Freeman", "PREVIEW", Category.PERSON_NAME);
    // "Morgan" should have been evicted — its fake was reassigned
    expect(store.getFake("Morgan")).toBeUndefined();
    expect(store.getCategory("Morgan")).toBeUndefined();
    // "Freeman" owns the fake now
    expect(store.getFake("Freeman")).toBe("PREVIEW");
    expect(store.getReal("PREVIEW")).toBe("Freeman");
    expect(store.size()).toBe(1);
  });

  test("update-in-place cleans up old fake reverse entry", () => {
    const store = new MemoryStore();
    store.put("alice@test.com", "fake1@test.com", Category.EMAIL);
    expect(store.getReal("fake1@test.com")).toBe("alice@test.com");
    // Remap alice to a different fake
    store.put("alice@test.com", "fake2@test.com", Category.EMAIL);
    expect(store.getFake("alice@test.com")).toBe("fake2@test.com");
    expect(store.getReal("fake2@test.com")).toBe("alice@test.com");
    // Old fake should no longer reverse-map
    expect(store.getReal("fake1@test.com")).toBeUndefined();
    expect(store.size()).toBe(1);
  });

  test("allMappings excludes evicted collision entries", () => {
    const store = new MemoryStore();
    store.put("real1", "samefake", Category.EMAIL);
    store.put("real2", "samefake", Category.PHONE);
    const mappings = store.allMappings();
    // Only real2 should remain — real1 was evicted by collision
    expect(mappings.size).toBe(1);
    expect(mappings.get("real2")).toBe("samefake");
    expect(mappings.has("real1")).toBe(false);
  });
});
