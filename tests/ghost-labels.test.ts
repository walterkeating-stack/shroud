/**
 * Ghost label tests — validates extractLabelStrict, cron/BOOT.md parsing,
 * case normalization, and persistence filtering.
 *
 * Test cases derived from /home/ka/shroud/logs-20260331/identity-fail.log
 * (1,157 entries across 6 distinct patterns).
 */

import { describe, test, expect, beforeEach } from "vitest";
import { AgentSessionTracker, _isValidAgentLabel, normalizeLabel } from "../src/agent-session.js";
import { writeFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("extractLabelStrict — ghost label prevention", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  // ─── Pattern 1: Bare user messages (no system prompt) → Unknown Agent ───

  describe("bare user messages → Unknown Agent", () => {
    const bareMessages = [
      "echo this back to me please: walter@keating.at",
      "Please format as JSON: walter@keating.at and server 10.0.1.5",
      "check <mailto:ops@internal.net|ops@internal.net> on host 192.168.1.50",
      "server 10.0.1.5 is important",
      "contact walter@keating.at please",
      "Contact john@acme.com please",
      "Hello world",
      "IP 10.1.0.1 is down",
      "Call +14155551234",
      "format: walter@keating.at",
    ];

    for (const msg of bareMessages) {
      test(`"${msg.slice(0, 50)}..." → Unknown Agent (strict)`, () => {
        const session = tracker.registerAgent(msg, [], "unknown", true);
        expect(session.agentLabel).toBe("Unknown Agent");
        expect(session.sessionId).toBe("transient");
      });
    }
  });

  // ─── Pattern 2: CLI sender metadata → Unknown Agent (strict has no "You are" fallback) ───

  test("CLI sender metadata → Unknown Agent (strict)", () => {
    const prompt = `Sender (untrusted metadata):
\`\`\`json
{
  "label": "cli",
  "id": "cli"
}
\`\`\`

[Mon 2026-03-30 19:00 GMT+2] test`;
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel).toBe("Unknown Agent");
  });

  // ─── Pattern 3: Cron prefix → correct agent ───

  describe("cron prefix parsing", () => {
    test("pj cron → PJ", () => {
      const prompt = "[cron:e8abb6f3-1234-5678-abcd-ef1234567890 pj: evening Walter digest]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("PJ");
    });

    test("endurance-coach cron → Coach Alessandra", () => {
      const prompt = "[cron:8f434bd5-abcd-1234-5678-ef1234567890 endurance-coach: 03:30 nightly memory sync]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("Coach Alessandra");
    });

    test("semiconalpha cron → SemiconAlpha Research", () => {
      const prompt = "[cron:7dcaa510-0000-1111-2222-333344445555 semiconalpha: 03:30 nightly memory sync]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("SemiconAlpha Research");
    });

    test("semiconalpha morning brief → SemiconAlpha Research", () => {
      const prompt = "[cron:b8c9d0e1-aaaa-bbbb-cccc-ddddeeeeeeee semiconalpha: 07:00 HKT morning brief (Liam)]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("SemiconAlpha Research");
    });

    test("pj morning ops sweep → PJ", () => {
      const prompt = "[cron:3dfd4636-1111-2222-3333-444455556666 pj: morning ops sweep]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("PJ");
    });

    test("unknown cron agent → title-cased short name", () => {
      const prompt = "[cron:aaaabbbb-cccc-dddd-eeee-ffffffffffff new-agent: daily task]";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toMatch(/New Agent/i);
    });
  });

  // ─── Pattern 4: BOOT.md header → correct agent ───

  describe("BOOT.md header parsing", () => {
    test("# BOOT (PJ — Main Agent) → PJ", () => {
      const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.\n\nBOOT.md:\n# BOOT (PJ — Main Agent)\nCheck all systems.";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("PJ");
    });

    test("# BOOT (Coach Alessandra — Alessandra) → Coach Alessandra", () => {
      const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.\n\nBOOT.md:\n# BOOT (Coach Alessandra — Alessandra)\nVerify training data.";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("Coach Alessandra");
    });

    test("# BOOT (SemiconAlpha Research) → SemiconAlpha Research", () => {
      const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.\n\nBOOT.md:\n# BOOT (SemiconAlpha Research)\nRun market data check.";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("SemiconAlpha Research");
    });

    test("# BOOT (Shroud Research) → Shroud Research", () => {
      const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.\n\nBOOT.md:\n# BOOT (Shroud Research)\nScan for new CVEs.";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      expect(session.agentLabel).toBe("Shroud Research");
    });

    test("strict mode does NOT extract 'Running A Boot Check' from boot preamble", () => {
      const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.";
      const session = tracker.registerAgent(prompt, [], "unknown", true);
      // Strict mode has no "You are" pattern — should be Unknown Agent
      expect(session.agentLabel).toBe("Unknown Agent");
    });
  });

  // ─── Pattern 5: Timestamped Slack messages → Unknown Agent (strict) ───

  test("timestamped Slack message without channel label → Unknown Agent (strict)", () => {
    const prompt = "[Mon 2026-03-30 21:20 GMT+2] Run memory_search with query 'latest briefing'.";
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel).toBe("Unknown Agent");
  });

  // ─── Pattern 6: WhatsApp metadata → WA sender ───

  test("WhatsApp metadata with e164 → WA Walter", () => {
    const prompt = `Conversation info (untrusted metadata):
\`\`\`json
{
  "message_id": "3AF030FCDA9AEDA22563",
  "sender_id": "+436648563582",
  "e164": "+436648563582",
  "sender": "Walter"
}
\`\`\``;
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel).toBe("WA Walter");
  });

  // ─── Channel labels (high confidence in both modes) ───

  test("conversation_label → agent name (strict)", () => {
    const prompt = `{"conversation_label": "#semiconalpha-research"}`;
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel.toLowerCase()).toContain("semiconalpha");
  });

  test("Slack message in #channel → agent name (strict)", () => {
    const prompt = "Slack message in #coach-alessandra from Walter: test";
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel.toLowerCase()).toContain("coach alessandra");
  });

  test("- Name: from IDENTITY.md → agent name (strict)", () => {
    const prompt = "System context.\n- Name: PJ\n- Creature: AI assistant\nMore instructions.";
    const session = tracker.registerAgent(prompt, [], "unknown", true);
    expect(session.agentLabel).toBe("PJ");
  });
});

// ─── Ghost label rejection ───

describe("_isValidAgentLabel — ghost rejection", () => {
  test("rejects 'Running A Boot Check'", () => {
    expect(_isValidAgentLabel("Running A Boot Check")).toBe(false);
  });

  test("rejects 'Checking System Status'", () => {
    expect(_isValidAgentLabel("Checking System Status")).toBe(false);
  });

  test("rejects 'Project Context'", () => {
    expect(_isValidAgentLabel("Project Context")).toBe(false);
  });

  test("rejects boot/system noise", () => {
    expect(_isValidAgentLabel("Boot Check")).toBe(false);
    expect(_isValidAgentLabel("startup")).toBe(false);
    expect(_isValidAgentLabel("health check")).toBe(false);
    expect(_isValidAgentLabel("self-test")).toBe(false);
    expect(_isValidAgentLabel("initialization")).toBe(false);
  });

  test("rejects generic noise", () => {
    expect(_isValidAgentLabel("test")).toBe(false);
    expect(_isValidAgentLabel("debug")).toBe(false);
    expect(_isValidAgentLabel("system")).toBe(false);
    expect(_isValidAgentLabel("admin")).toBe(false);
  });

  test("rejects context/metadata noise", () => {
    expect(_isValidAgentLabel("conversation")).toBe(false);
    expect(_isValidAgentLabel("session")).toBe(false);
    expect(_isValidAgentLabel("metadata")).toBe(false);
    expect(_isValidAgentLabel("message")).toBe(false);
  });

  test("accepts real agent names", () => {
    expect(_isValidAgentLabel("PJ")).toBe(true);
    expect(_isValidAgentLabel("Coach Alessandra")).toBe(true);
    expect(_isValidAgentLabel("SemiconAlpha Research")).toBe(true);
    expect(_isValidAgentLabel("Shroud Research")).toBe(true);
    expect(_isValidAgentLabel("Security Monitor")).toBe(true);
  });
});

// ─── Case normalization ───

describe("case-insensitive session dedup", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  test("'Semiconalpha Research' and 'SemiconAlpha Research' share one session", () => {
    const s1 = tracker.registerAgent("- Name: Semiconalpha Research\nAgent prompt.");
    const s2 = tracker.registerAgent("- Name: SemiconAlpha Research\nAgent prompt.");
    expect(s1.sessionId).toBe(s2.sessionId);
    expect(tracker.getAllSessions()).toHaveLength(1);
  });

  test("normalizeLabel produces consistent keys", () => {
    expect(normalizeLabel("SemiconAlpha Research")).toBe(normalizeLabel("semiconalpha research"));
    expect(normalizeLabel("  Coach  Alessandra ")).toBe(normalizeLabel("coach alessandra"));
    expect(normalizeLabel("PJ")).toBe(normalizeLabel("pj"));
  });

  test("getSessionByLabel is case-insensitive", () => {
    tracker.registerAgent("- Name: PJ\nAgent prompt.");
    expect(tracker.getSessionByLabel("pj")).not.toBeNull();
    expect(tracker.getSessionByLabel("PJ")).not.toBeNull();
    expect(tracker.getSessionByLabel("Pj")).not.toBeNull();
  });
});

// ─── Persistence: loadFromFile ghost filtering ───

describe("loadFromFile ghost filtering", () => {
  let tracker: AgentSessionTracker;
  let tmpDir: string;
  let filePath: string;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
    tmpDir = join(tmpdir(), `shroud-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(tmpDir, { recursive: true });
    filePath = join(tmpDir, "agent-sessions.json");
  });

  function writeSessions(sessions: any[]) {
    writeFileSync(filePath, JSON.stringify(sessions, null, 2));
  }

  test("filters out 'Running A Boot Check' on load", () => {
    writeSessions([
      { agentLabel: "Running A Boot Check", agentBuildId: "abc", sessionId: "s1", llmCallCount: 5 },
      { agentLabel: "PJ", agentBuildId: "def", sessionId: "s2", llmCallCount: 10 },
    ]);
    tracker.loadFromFile(filePath);
    const sessions = tracker.getAllSessions();
    expect(sessions).toHaveLength(1);
    expect(sessions[0].agentLabel).toBe("PJ");
  });

  test("filters out 'Unknown Agent' on load", () => {
    writeSessions([
      { agentLabel: "Unknown Agent", agentBuildId: "xyz", sessionId: "s3", llmCallCount: 2 },
      { agentLabel: "Shroud Research", agentBuildId: "ghi", sessionId: "s4", llmCallCount: 8 },
    ]);
    tracker.loadFromFile(filePath);
    const sessions = tracker.getAllSessions();
    expect(sessions).toHaveLength(1);
    expect(sessions[0].agentLabel).toBe("Shroud Research");
  });

  test("filters out 'Project Context' on load", () => {
    writeSessions([
      { agentLabel: "Project Context", agentBuildId: "aaa", sessionId: "s5", llmCallCount: 3 },
    ]);
    tracker.loadFromFile(filePath);
    expect(tracker.getAllSessions()).toHaveLength(0);
  });

  test("deduplicates case variants on load", () => {
    writeSessions([
      { agentLabel: "Semiconalpha Research", agentBuildId: "a1", sessionId: "s6", llmCallCount: 5 },
      { agentLabel: "SemiconAlpha Research", agentBuildId: "a2", sessionId: "s7", llmCallCount: 10 },
    ]);
    tracker.loadFromFile(filePath);
    const sessions = tracker.getAllSessions();
    // Second entry is skipped because normalized key already exists
    expect(sessions).toHaveLength(1);
    expect(sessions[0].agentLabel).toBe("Semiconalpha Research"); // first one wins
  });

  test("persistence roundtrip preserves valid agents", () => {
    tracker.registerAgent("- Name: PJ\nAgent prompt.");
    tracker.recordLlmCall();
    tracker.registerAgent("- Name: Coach Alessandra\nAgent prompt.");
    tracker.recordLlmCall();
    tracker.saveToFile(filePath);

    const tracker2 = new AgentSessionTracker();
    tracker2.loadFromFile(filePath);
    const labels = tracker2.getAllSessions().map(s => s.agentLabel).sort();
    expect(labels).toEqual(["Coach Alessandra", "PJ"]);
  });

  test("missing file does not throw", () => {
    expect(() => tracker.loadFromFile("/nonexistent/path.json")).not.toThrow();
  });
});

// ─── Full extractLabel (non-strict) still works for fetch fallback ───

describe("full extractLabel — fetch intercept fallback", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  test("'You are X' works in full mode", () => {
    const session = tracker.registerAgent("You are a helpful research assistant.", [], "unknown", false);
    expect(session.agentLabel).toBe("Helpful Research Assistant");
  });

  test("cron prefix works in full mode too", () => {
    const prompt = "[cron:e8abb6f3-1234-5678-abcd-ef1234567890 pj: evening Walter digest]";
    const session = tracker.registerAgent(prompt, [], "unknown", false);
    expect(session.agentLabel).toBe("PJ");
  });

  test("BOOT.md header works in full mode", () => {
    const prompt = "You are running a boot check.\n\n# BOOT (Shroud Research)\nCheck CVEs.";
    const session = tracker.registerAgent(prompt, [], "unknown", false);
    expect(session.agentLabel).toBe("Shroud Research");
  });

  test("'Running A Boot Check' is rejected by _isValidAgentLabel in full mode", () => {
    // Full mode would extract "Running A Boot Check" from "You are running a boot check"
    // but _isValidAgentLabel rejects it, so it falls through to BOOT.md header or Unknown
    const prompt = "You are running a boot check. Follow BOOT.md instructions exactly.";
    const session = tracker.registerAgent(prompt, [], "unknown", false);
    // Either catches the BOOT.md header (if present) or falls to Unknown
    expect(session.agentLabel).toBe("Unknown Agent");
  });
});
