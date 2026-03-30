/**
 * Agent identity extraction tests — based on REAL OpenClaw request bodies.
 *
 * Discovered from live debug (2026-03-30):
 *   body.system = [
 *     { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
 *     { type: "text", text: "System: [timestamp] Slack message in #pj-main from Walter Keating: test\n..." }
 *   ]
 *
 * The agent's SOUL.md is NOT in body.system. Agent identity comes from the
 * channel/conversation label in the session metadata (#pj-main, #coach-alessandra).
 */

import { describe, test, expect, beforeEach } from "vitest";
import { AgentSessionTracker, extractPromptSkeleton } from "../src/agent-session.js";

// Real OpenClaw event.prompt content (same as body.system[1])
function makePrompt(channel: string, agent: string) {
  return [
    "System: [2026-03-30 10:11:29 GMT+2] Slack message in #" + channel + " from Walter Keating: test",
    "",
    "Conversation info (untrusted metadata):",
    "```json",
    "{",
    '  "message_id": "1774858288.096029",',
    '  "sender_id": "U0AN2N5154L",',
    '  "conversation_label": "#' + channel + '",',
    '  "sender": "Walter Keating",',
    '  "timestamp": "Mon 2026-03-30 10:11 GMT+2"',
    "}",
    "```",
    "",
    "test",
  ].join("\n");
}

// Full body.system joined (block[0] framework + block[1] session context)
function makeFullSystem(channel: string) {
  return "You are Claude Code, Anthropic's official CLI for Claude.\n" + makePrompt(channel, "");
}

describe("Agent identity — real OpenClaw live format", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  // The critical tests: identify agent from channel label in session metadata
  test("PJ identified from #pj-main channel", () => {
    const session = tracker.registerAgent(makeFullSystem("pj-main"));
    expect(session.agentLabel).toBe("Pj");
  });

  test("Coach Alessandra identified from #coach-alessandra channel", () => {
    const session = tracker.registerAgent(makeFullSystem("coach-alessandra"));
    expect(session.agentLabel).toBe("Coach Alessandra");
  });

  test("Semiconalpha Research identified from channel", () => {
    const session = tracker.registerAgent(makeFullSystem("semiconalpha-research"));
    expect(session.agentLabel).toBe("Semiconalpha Research");
  });

  // event.prompt (without framework preamble) should also work
  test("event.prompt: PJ from channel label", () => {
    const session = tracker.registerAgent(makePrompt("pj-main", ""));
    expect(session.agentLabel).toBe("Pj");
  });

  test("event.prompt: Coach Alessandra from channel label", () => {
    const session = tracker.registerAgent(makePrompt("coach-alessandra", ""));
    expect(session.agentLabel).toBe("Coach Alessandra");
  });

  // Label-based consolidation: same channel = same session
  test("same channel, different timestamps = same session", () => {
    const s1 = tracker.registerAgent(makeFullSystem("pj-main"));
    const s2 = tracker.registerAgent(
      makeFullSystem("pj-main").replace("10:11:29", "14:22:00")
    );
    expect(s1.sessionId).toBe(s2.sessionId);
  });

  // Different channels = different agents
  test("different channels produce different sessions", () => {
    tracker.registerAgent(makeFullSystem("pj-main"));
    tracker.registerAgent(makeFullSystem("coach-alessandra"));
    tracker.registerAgent(makeFullSystem("semiconalpha-research"));
    expect(tracker.getAllSessions()).toHaveLength(3);
  });

  // Should NOT label everything as "Claude Code"
  test("never returns Claude Code as label for agent channels", () => {
    const channels = ["pj-main", "coach-alessandra", "semiconalpha-research"];
    for (const ch of channels) {
      const t = new AgentSessionTracker();
      const s = t.registerAgent(makeFullSystem(ch));
      expect(s.agentLabel).not.toBe("Claude Code");
    }
  });
});

// Backward compatibility: pure SOUL.md and IDENTITY.md formats still work
describe("Agent identity — SOUL.md and IDENTITY.md formats", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  test("IDENTITY.md: '- Name: PJ'", () => {
    const session = tracker.registerAgent("- Name: PJ\n- Creature: AI assistant\nYou are PJ.");
    expect(session.agentLabel).toBe("PJ");
  });

  test("SOUL.md: 'You are a research assistant'", () => {
    const session = tracker.registerAgent("You are a research assistant specializing in network security.");
    expect(session.agentLabel).toBe("Research Assistant");
  });

  test("SOUL.md: 'You are a customer support agent'", () => {
    const session = tracker.registerAgent("You are a customer support agent for a SaaS platform.");
    expect(session.agentLabel).toBe("Customer Support Agent");
  });

  test("IDENTITY.md: '- Name: Coach Alessandra'", () => {
    const session = tracker.registerAgent("- Name: Coach Alessandra\nYou help athletes.");
    expect(session.agentLabel).toBe("Coach Alessandra");
  });

  // Framework preamble + SOUL.md (--- separator)
  test("preamble + SOUL via --- separator", () => {
    const prompt = "You are Claude Code, Anthropic's official CLI.\n\n---\n\n- Name: PJ\nYou are PJ.";
    const session = tracker.registerAgent(prompt);
    expect(session.agentLabel).toBe("PJ");
  });

  // Framework preamble + SOUL without separator (last-match strategy)
  test("preamble + SOUL without separator: last 'You are' wins", () => {
    const prompt = "You are Claude Code, Anthropic's official CLI.\nYou are a research assistant.";
    const session = tracker.registerAgent(prompt);
    expect(session.agentLabel).toBe("Research Assistant");
  });
});

describe("Skeleton stripping", () => {
  test("skeleton strips XML blocks", () => {
    const skeleton = extractPromptSkeleton("You are PJ.\n<system-reminder>\nDynamic\n</system-reminder>\nMore.");
    expect(skeleton).toContain("PJ");
    expect(skeleton).not.toContain("Dynamic");
  });

  test("skeleton strips OpenClaw metadata", () => {
    const skeleton = extractPromptSkeleton(
      "System: [2026-03-30 09:53:11 GMT+2] Session sc-main-123\nYou are PJ."
    );
    expect(skeleton).toContain("PJ");
  });
});
