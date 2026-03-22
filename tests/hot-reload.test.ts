import { describe, it, expect, vi, beforeEach } from "vitest";
import { DetectorReloader } from "../src/hot-reload.js";

describe("DetectorReloader", () => {
  it("tracks reload count", () => {
    const callback = vi.fn();
    const reloader = new DetectorReloader({}, callback);

    expect(reloader.reloadCount).toBe(0);
    reloader.triggerReload("policy", { allowlist: [], denylist: [] });
    expect(reloader.reloadCount).toBe(1);
    expect(callback).toHaveBeenCalledWith("policy", { allowlist: [], denylist: [] });
  });

  it("supports all reload types", () => {
    const received: string[] = [];
    const reloader = new DetectorReloader({}, (what) => received.push(what));

    reloader.triggerReload("policy");
    reloader.triggerReload("customPatterns");
    reloader.triggerReload("detectorOverrides");

    expect(received).toEqual(["policy", "customPatterns", "detectorOverrides"]);
    expect(reloader.reloadCount).toBe(3);
  });

  it("reports watching state", () => {
    const reloader = new DetectorReloader({}, vi.fn());
    expect(reloader.isWatching).toBe(false);

    // Can't test start() without real files, but stop() should work
    reloader.stop();
    expect(reloader.isWatching).toBe(false);
  });
});

describe("Hot-reload integration with Obfuscator", () => {
  it("hot-reloads custom patterns", async () => {
    const { resolveConfig } = await import("../src/config.js");
    const { Obfuscator } = await import("../src/obfuscator.js");

    const config = resolveConfig({
      secretKey: "test-key-long-enough-for-validation-32chars",
      hotReload: true,
      persistentSalt: "test-salt",
    });
    const obfuscator = new Obfuscator(config);

    // Trigger hot-reload of custom patterns
    obfuscator.reloader!.triggerReload("customPatterns", [
      { name: "test_pattern", pattern: "SECRET-\\d+", category: "custom" },
    ]);

    // The new pattern should be active
    const result = obfuscator.obfuscate("Found SECRET-12345 in logs");
    expect(result.entities.length).toBeGreaterThan(0);

    await obfuscator.shutdown();
  });

  it("hot-reloads detector overrides", async () => {
    const { resolveConfig } = await import("../src/config.js");
    const { Obfuscator } = await import("../src/obfuscator.js");

    const config = resolveConfig({
      secretKey: "test-key-long-enough-for-validation-32chars",
      hotReload: true,
      persistentSalt: "test-salt",
    });
    const obfuscator = new Obfuscator(config);

    // Disable email detection via hot-reload
    obfuscator.reloader!.triggerReload("detectorOverrides", {
      email: { enabled: false },
    });

    const result = obfuscator.obfuscate("Contact john@example.com");
    // Email should not be detected since we disabled it
    const emailEntities = result.entities.filter((e) => e.category === "email");
    expect(emailEntities).toHaveLength(0);

    await obfuscator.shutdown();
  });
});
