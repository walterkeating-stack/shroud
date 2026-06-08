/**
 * Unit tests for per-agent ob/deob mode:
 *   - AgentModeResolver precedence (exact > wildcard > "*" > default)
 *   - Obfuscator behaviour for each mode (enforce / shadow / off)
 *   - Config parsing + validation
 *   - Module-level setCurrentAgentMode state
 *   - Shadow telemetry on AgentSessionTracker
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  AgentModeResolver,
  setAgentModeResolver,
  getAgentModeResolver,
  setCurrentAgentMode,
  getCurrentAgentMode,
  getCurrentAgentLabel,
  resetCurrentAgentMode,
} from "../src/agent-mode.js";
import { Obfuscator } from "../src/obfuscator.js";
import { resolveConfig, validateConfig } from "../src/config.js";
import { AgentSessionTracker } from "../src/agent-session.js";
import { RedactionFormatter } from "../src/redaction.js";
import { Category } from "../src/types.js";

const baseConfig = () => resolveConfig({ secretKey: "test-key-0123456789abcdef" });

describe("AgentModeResolver precedence", () => {
  it("returns 'enforce' by default when config is empty", () => {
    const r = new AgentModeResolver({});
    expect(r.resolve("anything")).toBe("enforce");
  });

  it("exact label match wins over wildcard", () => {
    const r = new AgentModeResolver({
      "research-bot": { mode: "off" },
      "research-*": { mode: "shadow" },
    });
    expect(r.resolve("research-bot")).toBe("off");
    expect(r.resolve("research-other")).toBe("shadow");
  });

  it("wildcard match wins over fallback '*'", () => {
    const r = new AgentModeResolver({
      "research-*": { mode: "shadow" },
      "*": { mode: "off" },
    });
    expect(r.resolve("research-bot")).toBe("shadow");
    expect(r.resolve("marketing-bot")).toBe("off");
  });

  it("'*' fallback applies when nothing else matches", () => {
    const r = new AgentModeResolver({ "*": { mode: "shadow" } });
    expect(r.resolve("any-agent")).toBe("shadow");
  });

  it("case-insensitive wildcard match", () => {
    const r = new AgentModeResolver({ "Research-*": { mode: "shadow" } });
    expect(r.resolve("research-bot")).toBe("shadow");
    expect(r.resolve("RESEARCH-BOT")).toBe("shadow");
  });

  it("listConfigured returns every entry plus the fallback", () => {
    const r = new AgentModeResolver({
      "alpha": { mode: "off" },
      "beta-*": { mode: "shadow" },
    });
    const list = r.listConfigured();
    expect(list.find(e => e.label === "alpha")?.mode).toBe("off");
    expect(list.find(e => e.label === "beta-*")?.source).toBe("wildcard");
    expect(list.find(e => e.label === "*")?.source).toBe("fallback");
  });
});

describe("Module-level current-agent-mode state", () => {
  beforeEach(() => resetCurrentAgentMode());

  it("starts at 'enforce' / 'Unknown Agent'", () => {
    expect(getCurrentAgentMode()).toBe("enforce");
    expect(getCurrentAgentLabel()).toBe("Unknown Agent");
  });

  it("setCurrentAgentMode updates both mode and label", () => {
    setCurrentAgentMode("agentdesk", "shadow");
    expect(getCurrentAgentMode()).toBe("shadow");
    expect(getCurrentAgentLabel()).toBe("agentdesk");
  });

  it("setAgentModeResolver swaps the module singleton", () => {
    const r = new AgentModeResolver({ "xyz": { mode: "off" } });
    setAgentModeResolver(r);
    expect(getAgentModeResolver().resolve("xyz")).toBe("off");
  });
});

describe("Obfuscator mode branching", () => {
  beforeEach(() => resetCurrentAgentMode());

  it("mode='enforce' replaces entities (default behaviour)", () => {
    const ob = new Obfuscator(baseConfig());
    const r = ob.obfuscate("Contact alice@acme-research.net today.", undefined, undefined, "enforce");
    expect(r.entities.length).toBeGreaterThan(0);
    expect(r.obfuscated).not.toContain("alice@acme-research.net");
    expect(r.shadow).toBe(false);
  });

  it("mode='shadow' detects entities but does NOT replace", () => {
    const ob = new Obfuscator(baseConfig());
    const input = "Contact alice@acme-research.net today.";
    const r = ob.obfuscate(input, undefined, undefined, "shadow");
    expect(r.entities.length).toBeGreaterThan(0);
    expect(r.obfuscated).toBe(input);      // payload unchanged
    expect(r.shadow).toBe(true);
  });

  it("mode='off' skips detection entirely", () => {
    const ob = new Obfuscator(baseConfig());
    const input = "Contact alice@acme-research.net today.";
    const r = ob.obfuscate(input, undefined, undefined, "off");
    expect(r.entities.length).toBe(0);
    expect(r.obfuscated).toBe(input);
  });

  it("falls back to module-level mode when no mode arg passed", () => {
    const ob = new Obfuscator(baseConfig());
    setCurrentAgentMode("x", "shadow");
    const input = "Email me at bob@acme-research.net";
    const r = ob.obfuscate(input);
    expect(r.obfuscated).toBe(input);
    expect(r.shadow).toBe(true);
  });

  it("explicit mode arg wins over module default", () => {
    const ob = new Obfuscator(baseConfig());
    setCurrentAgentMode("x", "off");
    const r = ob.obfuscate("Email charlie@acme-research.net", undefined, undefined, "enforce");
    expect(r.obfuscated).not.toContain("charlie@acme-research.net");
  });

  it("global dryRun still suppresses mutation in enforce mode", () => {
    const cfg = baseConfig();
    cfg.dryRun = true;
    const ob = new Obfuscator(cfg);
    const input = "dave@acme-research.net here";
    const r = ob.obfuscate(input, undefined, undefined, "enforce");
    expect(r.entities.length).toBeGreaterThan(0);
    expect(r.obfuscated).toBe(input);
  });

  it("deobfuscateWithStats is a no-op when mode='off'", () => {
    const ob = new Obfuscator(baseConfig());
    // First seed a mapping via enforce
    ob.obfuscate("See eve@acme-research.net", undefined, undefined, "enforce");
    // Now switch to off — the stored mapping should not be reversed
    setCurrentAgentMode("x", "off");
    const textWithFake = "See FAKE@example.com"; // unrelated fake
    const r = ob.deobfuscateWithStats(textWithFake);
    expect(r.replacementCount).toBe(0);
    expect(r.text).toBe(textWithFake);
  });
});

describe("Config parsing + validation", () => {
  it("parses the 'agents' block from plugin config", () => {
    const cfg = resolveConfig({
      secretKey: "k".repeat(32),
      agents: {
        "research-bot": { mode: "shadow" },
        "marketing-*": { mode: "off" },
        "*": { mode: "enforce" },
      },
    });
    expect(cfg.agents["research-bot"].mode).toBe("shadow");
    expect(cfg.agents["marketing-*"].mode).toBe("off");
  });

  it("ignores invalid mode values silently", () => {
    const cfg = resolveConfig({
      secretKey: "k".repeat(32),
      agents: { "bad": { mode: "invalid" as any } },
    });
    expect(cfg.agents["bad"]).toBeUndefined();
  });

  it("defaults dashboardModeControl to 'readonly'", () => {
    const cfg = resolveConfig({ secretKey: "k".repeat(32) });
    expect(cfg.dashboardModeControl).toBe("readonly");
  });

  it("env var SHROUD_DASHBOARD_MODE_CONTROL overrides config", () => {
    const prev = process.env.SHROUD_DASHBOARD_MODE_CONTROL;
    process.env.SHROUD_DASHBOARD_MODE_CONTROL = "mutate";
    try {
      const cfg = resolveConfig({ secretKey: "k".repeat(32), dashboardModeControl: "readonly" });
      expect(cfg.dashboardModeControl).toBe("mutate");
    } finally {
      if (prev === undefined) delete process.env.SHROUD_DASHBOARD_MODE_CONTROL;
      else process.env.SHROUD_DASHBOARD_MODE_CONTROL = prev;
    }
  });

  it("validateConfig warns when dashboardModeControl is 'mutate'", () => {
    const cfg = resolveConfig({ secretKey: "k".repeat(32), dashboardModeControl: "mutate" });
    const issues = validateConfig(cfg);
    expect(issues.some(i => i.field === "dashboardModeControl" && i.severity === "warning")).toBe(true);
  });

  it("validateConfig warns when any agent has mode='off'", () => {
    const cfg = resolveConfig({
      secretKey: "k".repeat(32),
      agents: { "x": { mode: "off" } },
    });
    const issues = validateConfig(cfg);
    expect(issues.some(i => i.field === "agents" && i.severity === "warning")).toBe(true);
  });
});

describe("RedactionFormatter.mask (static)", () => {
  it("short values get fully masked", () => {
    expect(RedactionFormatter.mask("ab", Category.EMAIL)).toBe("***");
    expect(RedactionFormatter.mask("abcd", Category.EMAIL)).toBe("***");
  });

  it("emails are masked local@***.tld", () => {
    expect(RedactionFormatter.mask("alice@acme.net", Category.EMAIL)).toMatch(/^a\*\*\*@\*\*\*\.net$/);
  });

  it("phones show last 4 digits", () => {
    expect(RedactionFormatter.mask("+1-415-555-0198", Category.PHONE)).toBe("***0198");
  });

  it("credit cards show last 4 digits in 4x4 shape", () => {
    expect(RedactionFormatter.mask("4012-3456-7890-1234", Category.CREDIT_CARD))
      .toBe("****-****-****-1234");
  });

  it("SSN shows last 4 digits", () => {
    expect(RedactionFormatter.mask("123-45-6789", Category.SSN)).toBe("***-**-6789");
  });

  it("IPv4 masks last two octets", () => {
    expect(RedactionFormatter.mask("10.42.88.7", Category.IP_ADDRESS)).toBe("10.42.*.*");
  });

  it("fallback: shows first 2 and last 2 chars", () => {
    expect(RedactionFormatter.mask("acme-corp", Category.ORG_NAME)).toBe("ac***rp");
  });
});

describe("AgentSessionTracker.recordShadow", () => {
  it("accumulates shadow detection counts and masked samples", () => {
    const tracker = new AgentSessionTracker();
    // Seed a session
    tracker.registerAgent("- Name: agentdesk\nResearch agent.", [], "claude", true);
    tracker.recordShadow(5, { credit_card: 5 }, [
      { category: "credit_card", masked: "40**-****-****-**12", detector: "credit_card", confidence: 0.85 },
    ]);
    const s = tracker.getCurrentSession();
    expect(s?.privacy.shadowDetections).toBe(5);
    expect(s?.privacy.shadowCategoryCounts?.credit_card).toBe(5);
    expect(s?.privacy.shadowSamples?.length).toBe(1);
    expect(s?.privacy.shadowSamples?.[0].masked).toBe("40**-****-****-**12");
  });

  it("caps shadowSamples ring buffer at 20", () => {
    const tracker = new AgentSessionTracker();
    tracker.registerAgent("- Name: researcher\nResearch agent.", [], "claude", true);
    for (let i = 0; i < 30; i++) {
      tracker.recordShadow(1, { phone: 1 }, [
        { category: "phone", masked: `mask-${i}`, detector: "phone", confidence: 0.9 },
      ]);
    }
    expect(tracker.getCurrentSession()?.privacy.shadowSamples?.length).toBe(20);
  });
});
