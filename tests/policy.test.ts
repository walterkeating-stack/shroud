/**
 * Tests for the versioned policy engine.
 */

import { describe, test, expect, beforeEach, afterAll } from "vitest";
import { PolicyEngine } from "../src/policy.js";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "shroud-policy-test-"));
});

afterAll(() => {
  try { rmSync(tempDir, { recursive: true }); } catch {}
});

describe("PolicyEngine — Basic CRUD", () => {
  test("default policy when no file exists", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    const policy = engine.getPolicy("any-build-id");
    expect(policy.injectionDetection).toBe("flag");
    expect(policy.injectionMinSeverity).toBe("low");
  });

  test("set and get agent policy", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.setAgentPolicy("agent-123", {
      label: "Research Agent",
      injectionDetection: "block",
      injectionMinSeverity: "high",
    });

    const policy = engine.getPolicy("agent-123");
    expect(policy.injectionDetection).toBe("block");
    expect(policy.injectionMinSeverity).toBe("high");
    expect(policy.label).toBe("Research Agent");
  });

  test("unknown agent falls back to defaults", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.setAgentPolicy("agent-123", { injectionDetection: "block" });

    const unknown = engine.getPolicy("unknown-agent");
    expect(unknown.injectionDetection).toBe("flag"); // default
  });

  test("disabled signatures merge default + agent", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.setDefaultPolicy({
      injectionDisabledSignatures: ["io_ignore_previous"],
    });
    engine.setAgentPolicy("agent-123", {
      injectionDisabledSignatures: ["rs_jailbreak"],
    });

    const policy = engine.getPolicy("agent-123");
    expect(policy.injectionDisabledSignatures).toContain("io_ignore_previous");
    expect(policy.injectionDisabledSignatures).toContain("rs_jailbreak");
  });

  test("remove agent policy", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.setAgentPolicy("agent-123", { injectionDetection: "block" });
    engine.removeAgentPolicy("agent-123");

    const policy = engine.getPolicy("agent-123");
    expect(policy.injectionDetection).toBe("flag"); // back to default
  });

  test("update default policy", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.setDefaultPolicy({ injectionDetection: "off" });

    const policy = engine.getPolicy("any-agent");
    expect(policy.injectionDetection).toBe("off");
  });
});

describe("PolicyEngine — Versioned Commit/Rollback", () => {
  test("commit creates a version", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    const commit = engine.commit("Initial policy");

    expect(commit.version).toBe(1);
    expect(commit.description).toBe("Initial policy");
    expect(commit.timestamp).toBeDefined();
  });

  test("sequential commits increment version", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    const c1 = engine.commit("Version 1");
    const c2 = engine.commit("Version 2");
    const c3 = engine.commit("Version 3");

    expect(c1.version).toBe(1);
    expect(c2.version).toBe(2);
    expect(c3.version).toBe(3);
    expect(engine.getCurrentVersion()).toBe(3);
  });

  test("rollback restores previous policy state", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));

    engine.setDefaultPolicy({ injectionDetection: "flag" });
    engine.commit("Flag mode");

    engine.setDefaultPolicy({ injectionDetection: "block" });
    engine.commit("Block mode");

    expect(engine.getPolicy("x").injectionDetection).toBe("block");

    // Rollback to version 1
    const restored = engine.rollback(1);
    expect(restored).not.toBeNull();
    expect(engine.getPolicy("x").injectionDetection).toBe("flag");
    expect(engine.getCurrentVersion()).toBe(1);
  });

  test("rollback to nonexistent version returns null", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    expect(engine.rollback(999)).toBeNull();
  });

  test("commit history is retrievable", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    engine.commit("First");
    engine.commit("Second");
    engine.commit("Third");

    const history = engine.getHistory();
    expect(history.commits).toHaveLength(3);
    expect(history.current).toBe(3);
    expect(history.commits[0].description).toBe("First");
    expect(history.commits[2].description).toBe("Third");
  });

  test("history capped at 50 commits", () => {
    const engine = new PolicyEngine(join(tempDir, "policy.json"));
    for (let i = 0; i < 60; i++) {
      engine.commit(`Commit ${i}`);
    }
    expect(engine.getHistory().commits.length).toBeLessThanOrEqual(50);
  });

  test("policy persists across engine instances", () => {
    const path = join(tempDir, "persist.json");

    const engine1 = new PolicyEngine(path);
    engine1.setAgentPolicy("agent-x", { injectionDetection: "block" });
    engine1.commit("Saved");

    const engine2 = new PolicyEngine(path);
    const policy = engine2.getPolicy("agent-x");
    expect(policy.injectionDetection).toBe("block");
    expect(engine2.getCurrentVersion()).toBe(1);
  });
});
