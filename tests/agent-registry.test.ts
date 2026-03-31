/**
 * Tests for agent registry — resolves agent identity from OpenClaw config.
 *
 * Uses a mock openclaw.json fixture with the same structure as the real config.
 * Tests every signal extraction pattern from logs-20260331/identity-fail.log.
 */

import { describe, test, expect, beforeEach, beforeAll, afterAll } from "vitest";
import { AgentRegistry } from "../src/agent-registry.js";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// ─── Mock OpenClaw fixture ───

let tmpDir: string;
let openclawDir: string;

const MOCK_CONFIG = {
  agents: {
    list: [
      {
        id: "main",
        name: "main",
        workspace: "", // will be set dynamically
        agentDir: "",
      },
      {
        id: "endurance-coach",
        name: "Coach Alessandra",
        identity: { name: "Coach Alessandra", emoji: "🏃" },
        workspace: "",
        agentDir: "",
      },
      {
        id: "semiconalpha-research",
        name: "SemiconAlpha Research",
        identity: { name: "SemiconAlpha Research" },
        workspace: "",
        agentDir: "",
      },
      {
        id: "shroud-research",
        name: "Shroud Research",
        identity: { name: "Shroud Research" },
        workspace: "",
        agentDir: "",
      },
    ],
  },
  bindings: [
    {
      agentId: "endurance-coach",
      match: { channel: "whatsapp", peer: { kind: "direct", id: "+4366488643158" } },
    },
    {
      agentId: "endurance-coach",
      match: { channel: "slack", peer: { kind: "channel", id: "C0AMN8YPPC7" } },
    },
    {
      agentId: "main",
      match: { channel: "slack", peer: { kind: "channel", id: "C0AMN8NUXPZ" } },
    },
    {
      agentId: "shroud-research",
      match: { channel: "slack", peer: { kind: "channel", id: "C0APTUHUSQM" } },
    },
    {
      agentId: "semiconalpha-research",
      match: { channel: "slack", peer: { kind: "channel", id: "C0AN09SPT29" } },
    },
    {
      type: "route",
      agentId: "shroud-research",
      match: { channel: "slack", accountId: "shroud-research" },
    },
  ],
};

// Mock session keys (simulates per-agent sessions.json)
const MOCK_SESSIONS: Record<string, Record<string, any>> = {
  main: {
    "agent:main:main": { model: "claude-sonnet-4-6" },
    "agent:main:whatsapp:direct:+436648563582": { model: "claude-sonnet-4-6" },
    "agent:main:slack:channel:c0amn8nuxpz": { model: "claude-sonnet-4-6" },
  },
  "endurance-coach": {
    "agent:endurance-coach:whatsapp:direct:+436648563582": { model: "gpt-5.2" },
    "agent:endurance-coach:slack:channel:c0amn8yppc7": { model: "claude-sonnet-4-6" },
    "agent:endurance-coach:whatsapp:direct:+4366488643158": { model: "claude-sonnet-4-6" },
  },
  "semiconalpha-research": {
    "agent:semiconalpha-research:slack:channel:c0an09spt29": { model: "claude-sonnet-4-6" },
    "agent:semiconalpha-research:whatsapp:direct:+85296899722": { model: "gpt-5.2" },
  },
  "shroud-research": {
    "agent:shroud-research:slack:channel:c0aptuhusqm": { model: "claude-sonnet-4-6" },
  },
};

beforeAll(() => {
  tmpDir = join(tmpdir(), `shroud-registry-test-${Date.now()}`);
  openclawDir = join(tmpDir, ".openclaw");

  // Create directory structure
  mkdirSync(join(openclawDir, "workspace"), { recursive: true });

  // Write main agent IDENTITY.md
  writeFileSync(join(openclawDir, "workspace", "IDENTITY.md"),
    "# IDENTITY\n- Name: PJ\n- Creature: helpful Aide\n");

  // Update config with real workspace paths
  const config = JSON.parse(JSON.stringify(MOCK_CONFIG));
  config.agents.list[0].workspace = join(openclawDir, "workspace");
  config.agents.list[1].workspace = join(openclawDir, "coach-alessandra");
  config.agents.list[2].workspace = join(openclawDir, "semiconalpha-workspace");
  config.agents.list[3].workspace = join(openclawDir, "shroud-workspace");

  // Write openclaw.json
  writeFileSync(join(openclawDir, "openclaw.json"), JSON.stringify(config, null, 2));

  // Write per-agent sessions.json
  for (const [agentId, sessions] of Object.entries(MOCK_SESSIONS)) {
    const sessionsDir = join(openclawDir, "agents", agentId, "sessions");
    mkdirSync(sessionsDir, { recursive: true });
    writeFileSync(join(sessionsDir, "sessions.json"), JSON.stringify(sessions, null, 2));
  }
});

afterAll(() => {
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});

// ─── Tests ───

describe("AgentRegistry — loading", () => {
  test("loads successfully from mock openclaw.json", () => {
    const reg = new AgentRegistry();
    expect(reg.load(openclawDir)).toBe(true);
    expect(reg.loaded).toBe(true);
    expect(reg.size).toBe(4);
  });

  test("returns false for missing config", () => {
    const reg = new AgentRegistry();
    expect(reg.load("/nonexistent/path")).toBe(false);
    expect(reg.loaded).toBe(false);
  });

  test("reads main agent name from IDENTITY.md", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);
    expect(reg.getCanonicalName("main")).toBe("PJ");
  });

  test("reads named agent identity from config", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);
    expect(reg.getCanonicalName("endurance-coach")).toBe("Coach Alessandra");
    expect(reg.getCanonicalName("semiconalpha-research")).toBe("SemiconAlpha Research");
    expect(reg.getCanonicalName("shroud-research")).toBe("Shroud Research");
  });

  test("getAllAgents returns all 4 agents", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);
    const agents = reg.getAllAgents();
    expect(agents).toHaveLength(4);
    const names = agents.map(a => a.canonicalName).sort();
    expect(names).toEqual(["Coach Alessandra", "PJ", "SemiconAlpha Research", "Shroud Research"]);
  });

  test("isKnownAgent matches by name and ID", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);
    expect(reg.isKnownAgent("PJ")).toBe(true);
    expect(reg.isKnownAgent("pj")).toBe(true);
    expect(reg.isKnownAgent("Coach Alessandra")).toBe(true);
    expect(reg.isKnownAgent("endurance-coach")).toBe(true);
    expect(reg.isKnownAgent("Ghost Agent")).toBe(false);
    expect(reg.isKnownAgent("Running A Boot Check")).toBe(false);
  });
});

describe("AgentRegistry — signal resolution", () => {
  let reg: AgentRegistry;

  beforeEach(() => {
    reg = new AgentRegistry();
    reg.load(openclawDir);
  });

  // ─── Slack channel ID signals ───

  test("Slack channel ID C0AMN8NUXPZ → PJ (main)", () => {
    const prompt = `{"conversation_label": "#pj-main", "channel_id": "C0AMN8NUXPZ"}`;
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  test("Slack channel ID C0APTUHUSQM → Shroud Research", () => {
    const prompt = `Slack message in #shroud-research\nChannel: C0APTUHUSQM`;
    expect(reg.resolve(prompt)).toBe("Shroud Research");
  });

  test("Slack channel ID C0AN09SPT29 → SemiconAlpha Research", () => {
    const prompt = `{"conversation_label": "#semiconalpha-research"}\nC0AN09SPT29`;
    expect(reg.resolve(prompt)).toBe("SemiconAlpha Research");
  });

  test("Slack channel ID C0AMN8YPPC7 → Coach Alessandra", () => {
    const prompt = `Message from C0AMN8YPPC7 user U0AN2N5154L`;
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });

  // ─── WhatsApp signals ───

  test("WhatsApp sender_id +4366488643158 → Coach Alessandra", () => {
    const prompt = `Conversation info (untrusted metadata):\n{"sender_id": "+4366488643158", "sender": "Alessandra"}`;
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });

  test("WhatsApp sender_id +436648563582 → PJ (ambiguous number defaults to main)", () => {
    // Walter's number (+436648563582) has sessions for both endurance-coach AND main.
    // Ambiguous numbers are skipped in session key enrichment.
    // With no explicit binding match, the WhatsApp fallback returns main agent (PJ).
    const prompt = `Conversation info:\n{"sender_id": "+436648563582", "sender": "Walter"}`;
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  test("WhatsApp e164 field also works", () => {
    const prompt = `{"e164": "+4366488643158", "sender": "Alessandra"}`;
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });

  // ─── Cron signals ───

  test("cron prefix 'pj:' → PJ (no match — main has id 'main' not 'pj')", () => {
    // "pj" is not an agent ID in the registry — "main" is.
    // The registry won't resolve this, but extractLabelStrict will via CRON_AGENT_MAP.
    const prompt = "[cron:e8abb6f3-1234-5678-abcd-ef1234567890 pj: evening Walter digest]";
    expect(reg.resolve(prompt)).toBeNull();
  });

  test("cron prefix 'endurance-coach:' → Coach Alessandra", () => {
    const prompt = "[cron:8f434bd5-abcd-1234-5678-ef1234567890 endurance-coach: 03:30 nightly memory sync]";
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });

  test("cron prefix 'semiconalpha-research:' → SemiconAlpha Research", () => {
    const prompt = "[cron:7dcaa510-0000-1111-2222-333344445555 semiconalpha-research: 03:30 nightly memory sync]";
    expect(reg.resolve(prompt)).toBe("SemiconAlpha Research");
  });

  test("cron prefix 'shroud-research:' → Shroud Research", () => {
    const prompt = "[cron:a1b2c3d4-shroud-stale-task-sweep shroud-research: daily sweep]";
    expect(reg.resolve(prompt)).toBe("Shroud Research");
  });

  // ─── Session key signals ───

  test("session key 'agent:shroud-research:' → Shroud Research", () => {
    const prompt = "lane=session:agent:shroud-research:slack:channel:c0aptuhusqm";
    expect(reg.resolve(prompt)).toBe("Shroud Research");
  });

  test("session key 'agent:main:' → PJ", () => {
    const prompt = "diagnostic: sessionId=main sessionKey=agent:main:main";
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  // ─── BOOT.md header ───

  test("BOOT.md header '# BOOT (PJ — Main Agent)' → PJ", () => {
    const prompt = "You are running a boot check.\n# BOOT (PJ — Main Agent)\nCheck systems.";
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  test("BOOT.md header '# BOOT (SemiconAlpha Research)' → SemiconAlpha Research", () => {
    const prompt = "Boot check.\n# BOOT (SemiconAlpha Research)\nRun checks.";
    expect(reg.resolve(prompt)).toBe("SemiconAlpha Research");
  });

  // ─── Slack message header ───

  test("'Slack message in #shroud-research' → Shroud Research", () => {
    const prompt = "Slack message in #shroud-research from Walter: test";
    expect(reg.resolve(prompt)).toBe("Shroud Research");
  });

  test("'Slack message in #coach-alessandra' → Coach Alessandra", () => {
    const prompt = "Slack message in #coach-alessandra from Walter: training update";
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });

  // ─── TUI/CLI → main agent ───

  test("CLI label → PJ (main)", () => {
    const prompt = `Sender (untrusted metadata):\n{"label": "cli", "id": "cli"}`;
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  test("TUI session → PJ (main)", () => {
    const prompt = "TUI session started. Enter your message.";
    expect(reg.resolve(prompt)).toBe("PJ");
  });

  // ─── conversation_label with agent name ───

  test("conversation_label '#semiconalpha-research' → SemiconAlpha Research", () => {
    const prompt = `{"conversation_label": "#semiconalpha-research"}`;
    expect(reg.resolve(prompt)).toBe("SemiconAlpha Research");
  });

  // ─── No signal → null ───

  test("bare user message → null", () => {
    expect(reg.resolve("Hello world")).toBeNull();
    expect(reg.resolve("email walter@keating.at about 10.0.1.5")).toBeNull();
    expect(reg.resolve("Contact john@acme.com please")).toBeNull();
  });

  test("empty prompt → null", () => {
    expect(reg.resolve("")).toBeNull();
  });

  test("unloaded registry → null", () => {
    const emptyReg = new AgentRegistry();
    expect(emptyReg.resolve("C0AMN8NUXPZ")).toBeNull();
  });
});

describe("AgentRegistry — session key enrichment", () => {
  test("WhatsApp number from session keys resolves correctly", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);

    // +85296899722 is only in semiconalpha-research session keys, not in bindings
    const prompt = `{"sender_id": "+85296899722", "sender": "Liam"}`;
    expect(reg.resolve(prompt)).toBe("SemiconAlpha Research");
  });

  test("Slack channel from session keys resolves correctly", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);

    // c0amn8yppc7 is in both bindings AND session keys for endurance-coach
    const prompt = `Channel info C0AMN8YPPC7`;
    expect(reg.resolve(prompt)).toBe("Coach Alessandra");
  });
});

describe("AgentRegistry — fallback for unknown agent IDs", () => {
  test("unknown agent ID title-cases", () => {
    const reg = new AgentRegistry();
    reg.load(openclawDir);
    expect(reg.getCanonicalName("new-agent")).toBe("New Agent");
    expect(reg.getCanonicalName("test_bot")).toBe("Test Bot");
  });
});
