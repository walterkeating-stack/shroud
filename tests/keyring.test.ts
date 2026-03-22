import { describe, it, expect, vi, beforeEach } from "vitest";
import { KeyRing, VersionedKey } from "../src/keyring.js";

describe("KeyRing", () => {
  const key1 = "abcdefghijklmnopqrstuvwxyz123456";
  const key2 = "zyxwvutsrqponmlkjihgfedcba654321";
  const key3 = "00112233445566778899aabbccddeeff";

  it("creates from single key (backward compat)", () => {
    const ring = KeyRing.fromSingleKey(key1);
    expect(ring.size).toBe(1);
    expect(ring.activeKey().key).toBe(key1);
    expect(ring.activeKey().version).toBe(1);
  });

  it("creates from multiple keys", () => {
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z" },
    ]);
    expect(ring.size).toBe(2);
    // Active = highest version
    expect(ring.activeKey().version).toBe(2);
    expect(ring.activeKey().key).toBe(key2);
  });

  it("respects explicit activeVersion", () => {
    const ring = new KeyRing(
      [
        { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
        { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z" },
      ],
      1, // force v1 active
    );
    expect(ring.activeKey().version).toBe(1);
  });

  it("throws on empty keys", () => {
    expect(() => new KeyRing([])).toThrow("at least one key");
  });

  it("throws on duplicate versions", () => {
    expect(() =>
      new KeyRing([
        { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
        { version: 1, key: key2, createdAt: "2025-06-01T00:00:00Z" },
      ]),
    ).toThrow("unique");
  });

  it("addKey increments version and makes it active", () => {
    const ring = KeyRing.fromSingleKey(key1);
    const vk = ring.addKey(key2);
    expect(vk.version).toBe(2);
    expect(ring.activeKey().version).toBe(2);
    expect(ring.size).toBe(2);
  });

  it("retireKey soft-disables a key", () => {
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z" },
    ]);
    ring.retireKey(2);
    // Active falls back to highest non-retired
    expect(ring.activeKey().version).toBe(1);
    // Retired key still in allKeys (for deobfuscation)
    expect(ring.allKeys().length).toBe(2);
  });

  it("expired keys are excluded from activeKey", () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z", expiresAt: pastDate },
    ]);
    expect(ring.activeKey().version).toBe(1);
  });

  it("expired keys excluded from allKeys", () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z", expiresAt: pastDate },
    ]);
    expect(ring.allKeys().length).toBe(1);
    expect(ring.allKeysRaw().length).toBe(2);
  });

  it("pruneExpired removes and returns expired keys", () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z", expiresAt: pastDate },
    ]);
    const pruned = ring.pruneExpired();
    expect(pruned.length).toBe(1);
    expect(pruned[0].version).toBe(2);
    expect(ring.size).toBe(1);
  });

  it("throws when all keys expired", () => {
    const pastDate = new Date(Date.now() - 1000).toISOString();
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z", expiresAt: pastDate },
    ]);
    expect(() => ring.activeKey()).toThrow("No valid");
  });

  it("getKey returns specific version", () => {
    const ring = new KeyRing([
      { version: 1, key: key1, createdAt: "2025-01-01T00:00:00Z" },
      { version: 2, key: key2, createdAt: "2025-06-01T00:00:00Z" },
    ]);
    expect(ring.getKey(1)?.key).toBe(key1);
    expect(ring.getKey(99)).toBeUndefined();
  });

  it("toJSON serializes correctly", () => {
    const ring = KeyRing.fromSingleKey(key1);
    const json = ring.toJSON();
    expect(json.keys.length).toBe(1);
    expect(json.activeVersion).toBe(1);
  });
});

describe("KeyRing integration with Obfuscator", () => {
  it("key rotation preserves existing mappings", async () => {
    const { resolveConfig } = await import("../src/config.js");
    const { Obfuscator } = await import("../src/obfuscator.js");

    const config = resolveConfig({
      secretKey: "test-key-long-enough-for-validation-32chars",
      persistentSalt: "test-salt",
    });
    const obfuscator = new Obfuscator(config);

    // Obfuscate with original key
    const result1 = obfuscator.obfuscate("Contact john@acme.com for details");
    expect(result1.entities.length).toBeGreaterThan(0);
    const fakeBefore = result1.mappingsUsed["john@acme.com"];

    // Rotate key
    const vk = obfuscator.rotateKey("new-key-long-enough-for-validation-32chars");
    expect(vk.version).toBe(2);

    // Old mapping still deobfuscates
    const restored = obfuscator.deobfuscate(result1.obfuscated);
    expect(restored).toContain("john@acme.com");

    // New obfuscations use new key (will produce new fake for new values)
    const result2 = obfuscator.obfuscate("Contact jane@acme.com now");
    expect(result2.entities.length).toBeGreaterThan(0);
  });

  it("session export/import works across key rotations", async () => {
    const { resolveConfig } = await import("../src/config.js");
    const { Obfuscator } = await import("../src/obfuscator.js");

    const config = resolveConfig({
      secretKey: "test-key-long-enough-for-validation-32chars",
      sessionHandoff: true,
      persistentSalt: "test-salt",
    });

    const ob1 = new Obfuscator(config);
    ob1.obfuscate("Contact john@acme.com");
    const blob = ob1.exportSession();

    // New obfuscator with rotated key can still import
    const ob2 = new Obfuscator(config);
    ob2.rotateKey("rotated-key-long-enough-for-validation-32");
    // Import should try all keys including original
    ob2.importSession(blob);
  });
});
