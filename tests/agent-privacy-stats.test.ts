/**
 * Per-agent privacy stats — obfuscation/deobfuscation tracking.
 *
 * Tests that AgentSessionTracker correctly accumulates per-agent
 * obfuscation calls, entity counts, category breakdowns, and
 * deobfuscation replacement counts.
 */

import { describe, test, expect, beforeEach } from "vitest";
import { AgentSessionTracker } from "../src/agent-session.js";

describe("Per-agent privacy stats", () => {
  let tracker: AgentSessionTracker;

  beforeEach(() => {
    tracker = new AgentSessionTracker();
  });

  // ── Obfuscation tracking ──

  test("recordObfuscation increments entity count for current agent", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(5, { ip_address: 3, hostname: 2 });

    const session = tracker.getCurrentSession();
    expect(session).not.toBeNull();
    expect(session!.privacy.obfuscationCalls).toBe(1);
    expect(session!.privacy.entitiesObfuscated).toBe(5);
    expect(session!.privacy.categoryCounts).toEqual({ ip_address: 3, hostname: 2 });
  });

  test("multiple obfuscation calls accumulate", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(3, { email: 2, phone: 1 });
    tracker.recordObfuscation(7, { email: 1, ip_address: 4, hostname: 2 });

    const session = tracker.getCurrentSession();
    expect(session!.privacy.obfuscationCalls).toBe(2);
    expect(session!.privacy.entitiesObfuscated).toBe(10);
    expect(session!.privacy.categoryCounts).toEqual({
      email: 3, phone: 1, ip_address: 4, hostname: 2,
    });
  });

  test("recordObfuscation with no categories still increments call count", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(0);

    const session = tracker.getCurrentSession();
    expect(session!.privacy.obfuscationCalls).toBe(1);
    expect(session!.privacy.entitiesObfuscated).toBe(0);
    expect(session!.privacy.categoryCounts).toEqual({});
  });

  // ── Deobfuscation tracking ──

  test("recordDeobfuscation increments replacement count", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordDeobfuscation(3);

    const session = tracker.getCurrentSession();
    expect(session!.privacy.deobfuscationCalls).toBe(1);
    expect(session!.privacy.replacementsDeobfuscated).toBe(3);
  });

  test("multiple deobfuscation calls accumulate", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordDeobfuscation(2);
    tracker.recordDeobfuscation(5);
    tracker.recordDeobfuscation(1);

    const session = tracker.getCurrentSession();
    expect(session!.privacy.deobfuscationCalls).toBe(3);
    expect(session!.privacy.replacementsDeobfuscated).toBe(8);
  });

  // ── Per-agent isolation ──

  test("different agents have independent privacy stats", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(10, { ip_address: 8, hostname: 2 });
    tracker.recordDeobfuscation(4);

    tracker.registerAgent("- Name: Coach Alessandra\nYou are an endurance coach.", [], "claude", true);
    tracker.recordObfuscation(3, { person_name: 2, email: 1 });
    tracker.recordDeobfuscation(1);

    const sessions = tracker.getAllSessions();
    const pj = sessions.find(s => s.agentLabel === "PJ");
    const coach = sessions.find(s => s.agentLabel === "Coach Alessandra");

    expect(pj!.privacy.entitiesObfuscated).toBe(10);
    expect(pj!.privacy.replacementsDeobfuscated).toBe(4);
    expect(pj!.privacy.categoryCounts).toEqual({ ip_address: 8, hostname: 2 });

    expect(coach!.privacy.entitiesObfuscated).toBe(3);
    expect(coach!.privacy.replacementsDeobfuscated).toBe(1);
    expect(coach!.privacy.categoryCounts).toEqual({ person_name: 2, email: 1 });
  });

  test("switching back to a previous agent resumes its stats", () => {
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(5, { ip_address: 5 });

    tracker.registerAgent("- Name: Coach Alessandra\nYou are an endurance coach.", [], "claude", true);
    tracker.recordObfuscation(2, { email: 2 });

    // Switch back to PJ
    tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    tracker.recordObfuscation(3, { hostname: 3 });

    const pj = tracker.getAllSessions().find(s => s.agentLabel === "PJ");
    expect(pj!.privacy.obfuscationCalls).toBe(2);
    expect(pj!.privacy.entitiesObfuscated).toBe(8);
    expect(pj!.privacy.categoryCounts).toEqual({ ip_address: 5, hostname: 3 });
  });

  // ── No-op for unidentified agents ──

  test("recordObfuscation is no-op when no agent registered", () => {
    tracker.recordObfuscation(5, { email: 5 });
    // Should not throw, sessions should be empty
    expect(tracker.getAllSessions()).toHaveLength(0);
  });

  test("recordDeobfuscation is no-op when no agent registered", () => {
    tracker.recordDeobfuscation(3);
    expect(tracker.getAllSessions()).toHaveLength(0);
  });

  // ── Privacy field initialization ──

  test("new session has zeroed privacy stats", () => {
    const session = tracker.registerAgent("- Name: PJ\nYou are a network automation agent.", [], "claude", true);
    expect(session.privacy).toEqual({
      obfuscationCalls: 0,
      deobfuscationCalls: 0,
      entitiesObfuscated: 0,
      replacementsDeobfuscated: 0,
      categoryCounts: {},
    });
  });

  test("Unknown Agent gets privacy stats on transient session", () => {
    const session = tracker.registerAgent("short", [], "claude", true);
    expect(session.agentLabel).toBe("Unknown Agent");
    expect(session.privacy).toBeDefined();
    expect(session.privacy.obfuscationCalls).toBe(0);
  });

  // ── Persistence roundtrip ──

  test("privacy stats survive loadFromFile", () => {
    const { mkdtempSync, writeFileSync, rmSync } = require("node:fs");
    const { join } = require("node:path");
    const { tmpdir } = require("node:os");

    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-privacy-test-"));
    const filePath = join(tmpDir, "agent-sessions.json");

    // Write sessions with privacy data
    const sessions = [{
      agentLabel: "PJ",
      agentBuildId: "abc123",
      sessionId: "s1",
      llmCallCount: 10,
      securityEventCount: 2,
      detectedModel: "claude",
      channels: ["slack"],
      classification: { role: "Network Engineering", confidencePct: 90, confidence: "high", colour: "#3fb950", signals: ["network"] },
      toolInventory: ["exec"],
      startedAt: Date.now(),
      lastCallAt: Date.now(),
      soulExtract: "",
      behavior: { toolFrequency: {}, totalToolCalls: 0, avgSimilarity: 1, driftCheckCount: 0, recentSimilarities: [], archetype: "Unknown", archetypeConfidence: 0 },
      privacy: {
        obfuscationCalls: 15,
        deobfuscationCalls: 8,
        entitiesObfuscated: 42,
        replacementsDeobfuscated: 12,
        categoryCounts: { ip_address: 20, hostname: 15, email: 7 },
      },
    }];
    writeFileSync(filePath, JSON.stringify(sessions));

    // Load into fresh tracker
    const tracker2 = new AgentSessionTracker();
    tracker2.loadFromFile(filePath);

    const loaded = tracker2.getAllSessions();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].privacy.obfuscationCalls).toBe(15);
    expect(loaded[0].privacy.deobfuscationCalls).toBe(8);
    expect(loaded[0].privacy.entitiesObfuscated).toBe(42);
    expect(loaded[0].privacy.replacementsDeobfuscated).toBe(12);
    expect(loaded[0].privacy.categoryCounts).toEqual({ ip_address: 20, hostname: 15, email: 7 });

    rmSync(tmpDir, { recursive: true, force: true });
  });

  test("loadFromFile handles missing privacy field gracefully", () => {
    const { mkdtempSync, writeFileSync, rmSync } = require("node:fs");
    const { join } = require("node:path");
    const { tmpdir } = require("node:os");

    const tmpDir = mkdtempSync(join(tmpdir(), "shroud-privacy-test-"));
    const filePath = join(tmpDir, "agent-sessions.json");

    // Old format without privacy field
    const sessions = [{
      agentLabel: "PJ",
      agentBuildId: "abc123",
      sessionId: "s1",
      llmCallCount: 10,
      channels: ["slack"],
      classification: { role: "Network Engineering", confidencePct: 90, confidence: "high", colour: "#3fb950", signals: [] },
      toolInventory: [],
      startedAt: Date.now(),
      lastCallAt: Date.now(),
    }];
    writeFileSync(filePath, JSON.stringify(sessions));

    const tracker2 = new AgentSessionTracker();
    tracker2.loadFromFile(filePath);

    const loaded = tracker2.getAllSessions();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].privacy).toEqual({
      obfuscationCalls: 0,
      deobfuscationCalls: 0,
      entitiesObfuscated: 0,
      replacementsDeobfuscated: 0,
      categoryCounts: {},
    });

    rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe("Role taxonomy — consumer categories", () => {
  test("Healthcare / Therapy detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: Wellness Bot\nYou are a mental health therapist helping users manage anxiety and wellbeing.", [], "claude", true);
    expect(session.classification.role).toBe("Healthcare / Therapy");
  });

  test("Education / Tutoring detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: MathHelper\nYou are a tutor who teaches students calculus and helps with homework.", [], "claude", true);
    expect(session.classification.role).toBe("Education / Tutoring");
  });

  test("Entertainment / Adult detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: Companion\nYou are an adult roleplay companion for intimate and erotic conversations.", [], "claude", true);
    expect(session.classification.role).toBe("Entertainment / Adult");
  });

  test("Gaming detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: GameMaster\nYou are a dungeon master running an RPG quest for the player.", [], "claude", true);
    expect(session.classification.role).toBe("Gaming");
  });

  test("Chatbot / Conversational detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: ChatBuddy\nYou are a friendly chatbot for casual conversation and chit-chat.", [], "claude", true);
    expect(session.classification.role).toBe("Chatbot / Conversational");
  });

  test("E-commerce detected from prompt", () => {
    const tracker = new AgentSessionTracker();
    const session = tracker.registerAgent("- Name: ShopBot\nYou are a shopping assistant helping users with e-commerce checkout and product search.", [], "claude", true);
    expect(session.classification.role).toBe("E-commerce");
  });
});
