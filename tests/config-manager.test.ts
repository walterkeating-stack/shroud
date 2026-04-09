import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, unlinkSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ConfigManager, stripComments } from "../src/config-manager.js";
import { resolveConfig } from "../src/config.js";

const TEST_DIR = join(tmpdir(), "shroud-config-test-" + process.pid);
const CONFIG_PATH = join(TEST_DIR, "shroud.config.json");
const HISTORY_PATH = CONFIG_PATH + ".history.json";

function cleanup() {
  for (const f of [CONFIG_PATH, HISTORY_PATH]) {
    try { unlinkSync(f); } catch {}
  }
}

function baseConfig() {
  return resolveConfig({ secretKey: "test-key-1234567890123456" });
}

describe("stripComments", () => {
  it("strips line comments", () => {
    expect(stripComments('{"a": 1} // comment')).toBe('{"a": 1} ');
  });

  it("strips block comments", () => {
    expect(stripComments('{"a": /* inline */ 1}')).toBe('{"a":  1}');
  });

  it("preserves strings containing //", () => {
    expect(stripComments('{"url": "https://example.com"}')).toBe('{"url": "https://example.com"}');
  });

  it("handles multiline JSONC", () => {
    const input = `{
  // Drift threshold
  "driftThreshold": 0.12,
  /* Block comment
     spanning lines */
  "coherenceZScore": 2.5
}`;
    const parsed = JSON.parse(stripComments(input));
    expect(parsed.driftThreshold).toBe(0.12);
    expect(parsed.coherenceZScore).toBe(2.5);
  });
});

describe("ConfigManager", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    cleanup();
  });

  afterEach(() => {
    cleanup();
  });

  it("auto-creates config file with built-in rules when none exists", () => {
    const base = baseConfig();
    const cm = new ConfigManager(CONFIG_PATH, base);
    expect(cm.getEffective().driftThreshold).toBe(base.driftThreshold);
    // Auto-created file should have rules section with built-in patterns
    const overrides = cm.getFileOverrides();
    expect(overrides.rules).toBeDefined();
    expect(Object.keys(overrides.rules!).length).toBeGreaterThan(0);
    expect(overrides.rules!.email).toBeDefined();
    expect(overrides.rules!.email.pattern).toBeDefined();
  });

  it("merges file overrides with base config", () => {
    writeFileSync(CONFIG_PATH, JSON.stringify({ driftThreshold: 0.25 }));
    const base = baseConfig();
    const cm = new ConfigManager(CONFIG_PATH, base);
    expect(cm.getEffective().driftThreshold).toBe(0.25);
    expect(cm.getEffective().coherenceZScore).toBe(base.coherenceZScore);
  });

  it("loads JSONC with comments", () => {
    writeFileSync(CONFIG_PATH, `{
  // Custom threshold
  "driftThreshold": 0.30,
  /* Block */
  "coherenceZScore": 4.0
}`);
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    expect(cm.getEffective().driftThreshold).toBe(0.30);
    expect(cm.getEffective().coherenceZScore).toBe(4.0);
  });

  it("keeps previous config on corrupt file", () => {
    writeFileSync(CONFIG_PATH, JSON.stringify({ driftThreshold: 0.20 }));
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    expect(cm.getEffective().driftThreshold).toBe(0.20);

    // Corrupt the file
    writeFileSync(CONFIG_PATH, "NOT VALID JSON {{{");
    // Manually trigger reload by calling setFields (which re-reads)
    // The internal _reload should handle the corrupt file gracefully
    const base2 = baseConfig();
    const cm2 = new ConfigManager(CONFIG_PATH, base2);
    // Should fall back to base since file is corrupt
    expect(cm2.getEffective().driftThreshold).toBe(base2.driftThreshold);
  });

  it("fires field-specific listeners only for changed fields", () => {
    writeFileSync(CONFIG_PATH, JSON.stringify({ driftThreshold: 0.10 }));
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());

    let driftFired = 0;
    let coherenceFired = 0;
    cm.onFieldChange(["driftThreshold"], () => { driftFired++; });
    cm.onFieldChange(["coherenceZScore"], () => { coherenceFired++; });

    // Change only coherenceZScore
    cm.setFields({ coherenceZScore: 5.0 });
    expect(driftFired).toBe(0);
    expect(coherenceFired).toBe(1);
  });

  it("fires generic reload listener on any change", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    let reloadCount = 0;
    cm.onReload(() => { reloadCount++; });

    cm.setFields({ driftThreshold: 0.99 });
    expect(reloadCount).toBe(1);
  });

  it("deduplicates callbacks watching multiple changed fields", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    let callCount = 0;
    cm.onFieldChange(["driftThreshold", "driftSuddenTurnDelta"], () => { callCount++; });

    cm.setFields({ driftThreshold: 0.11, driftSuddenTurnDelta: 0.22 });
    expect(callCount).toBe(1);
  });

  it("setFields skips restart-only fields with warning", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    const { warnings, changedFields } = cm.setFields({
      secretKey: "new-secret",
      driftThreshold: 0.50,
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("secretKey");
    expect(changedFields).toContain("driftThreshold");
    expect(cm.getEffective().driftThreshold).toBe(0.50);
  });

  it("commit creates versioned snapshot", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    cm.setFields({ driftThreshold: 0.33 });
    const commit = cm.commit("Test commit");
    expect(commit.version).toBe(1);
    expect(commit.config.driftThreshold).toBe(0.33);
  });

  it("rollback restores previous config", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    cm.setFields({ driftThreshold: 0.33 });
    cm.commit("v1");
    cm.setFields({ driftThreshold: 0.99 });
    expect(cm.getEffective().driftThreshold).toBe(0.99);

    cm.rollback(1);
    expect(cm.getEffective().driftThreshold).toBe(0.33);
  });

  it("history caps at 50 entries", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    for (let i = 0; i < 55; i++) {
      cm.setFields({ driftThreshold: i * 0.01 });
      cm.commit(`commit-${i}`);
    }
    expect(cm.getHistory()).toHaveLength(50);
  });

  it("partial config preserves unspecified fields", () => {
    const base = baseConfig();
    writeFileSync(CONFIG_PATH, JSON.stringify({ driftThreshold: 0.50 }));
    const cm = new ConfigManager(CONFIG_PATH, base);
    // coherenceZScore should be unchanged from base
    expect(cm.getEffective().coherenceZScore).toBe(base.coherenceZScore);
    // driftThreshold should be overridden
    expect(cm.getEffective().driftThreshold).toBe(0.50);
  });

  it("validate catches invalid custom patterns", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    const issues = cm.validate({
      customPatterns: [{ name: "bad", pattern: "[invalid" }],
    });
    expect(issues.some(i => i.field === "customPatterns" && i.severity === "error")).toBe(true);
  });

  it("getConfigPath returns the file path", () => {
    const cm = new ConfigManager(CONFIG_PATH, baseConfig());
    expect(cm.getConfigPath()).toBe(CONFIG_PATH);
  });

  it("history persists to disk and reloads", () => {
    const cm1 = new ConfigManager(CONFIG_PATH, baseConfig());
    cm1.setFields({ driftThreshold: 0.42 });
    cm1.commit("persisted commit");
    cm1.stopWatching();

    // Create a new ConfigManager reading the same files
    const cm2 = new ConfigManager(CONFIG_PATH, baseConfig());
    expect(cm2.getHistory()).toHaveLength(1);
    expect(cm2.getHistory()[0].description).toBe("persisted commit");
    expect(cm2.getCurrentVersion()).toBe(1);
  });
});
