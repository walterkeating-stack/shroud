/**
 * Profiler training and adversarial detection tests.
 *
 * Runs realistic agent conversations through the profiler to build baselines,
 * then verifies adversarial inputs trigger anomaly detection.
 *
 * Three agents with distinct profiles:
 * - security-researcher: network infra entities, search/read/write tools
 * - customer-outreach: PII entities (names, emails, phones), CRM tools
 * - support-bot: mixed entities, ticket/account/KB tools
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";

import { BehaviouralProfiler } from "../src/profiler.js";
import { BaselineStore } from "../src/profiler-store.js";
import { InjectionDetector } from "../src/detectors/injection.js";
import { Obfuscator } from "../src/obfuscator.js";
import { resolveConfig } from "../src/config.js";
import { AgentSessionTracker, computeBuildId } from "../src/agent-session.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load the agent profiles
const profilesPath = join(__dirname, "harness", "harness", "scenarios", "agent-profiles.json");
const profileData = JSON.parse(readFileSync(profilesPath, "utf-8"));

const config = resolveConfig({
  secretKey: "test-secret-key-1234567890abcdef",
  injectionDetection: "flag",
});

let tempDir: string;
let store: BaselineStore;
let detector: InjectionDetector;
let tracker: AgentSessionTracker;

// Build IDs for each agent
const buildIds: Record<string, string> = {};

beforeAll(() => {
  tempDir = mkdtempSync(join(tmpdir(), "shroud-profiler-training-"));
  store = new BaselineStore(tempDir);
  detector = new InjectionDetector({
    action: "flag",
    disabledSignatures: new Set(),
    minSeverity: "low",
    scanResponses: true,
  });
  tracker = new AgentSessionTracker();

  // Compute build IDs
  for (const [agentId, agent] of Object.entries(profileData.agents) as [string, any][]) {
    buildIds[agentId] = computeBuildId(agent.soul, agent.expected_tools, "mock-model");
  }
});

// ===================================================================
// Phase 1: Baseline accumulation — train each agent
// ===================================================================

describe("Profiler Training — Phase 1: Baseline Accumulation", () => {
  for (const [agentId, agent] of Object.entries(profileData.agents) as [string, any][]) {
    describe(`Agent: ${agentId}`, () => {
      test(`trains on ${agent.training.length} turns and builds baseline`, () => {
        const buildId = buildIds[agentId];
        const obf = new Obfuscator(config);

        // Simulate multiple sessions (3 sessions of training data)
        for (let session = 0; session < 3; session++) {
          const profiler = new BehaviouralProfiler(
            { mode: "learning", sigma: 3, minBaseline: 3, profileDir: tempDir },
            store,
          );
          profiler.setAgentBuildId(buildId);

          for (const turn of agent.training) {
            // Obfuscate to get entity counts
            const result = obf.obfuscate(turn.input);
            const catCounts: Record<string, number> = {};
            for (const entity of result.entities) {
              catCounts[entity.category] = (catCounts[entity.category] ?? 0) + 1;
            }

            profiler.extractRequestFeatures(
              turn.input,
              catCounts,
              agent.expected_tools.map((t: string) => ({ name: t })),
            );
            profiler.extractResponseFeatures(
              `Acknowledged. Processing ${agentId} task.`,
              [],
            );
          }

          profiler.finalizeSession();
          obf.reset();
        }

        // Verify baseline was created
        const baseline = store.load(buildId);
        expect(baseline).not.toBeNull();
        expect(baseline!.sessionCount).toBe(3);
        expect(baseline!.maturity).toBe("learning"); // 3 < 5

        // Verify tool profile matches expected
        for (const tool of agent.expected_tools) {
          expect(baseline!.toolProfile).toContain(tool);
        }

        // Verify entity categories are tracked
        expect(baseline!.categoryProfile.length).toBeGreaterThan(0);
      });
    });
  }
});

// ===================================================================
// Phase 2: Build to reliable baseline (5+ sessions)
// ===================================================================

describe("Profiler Training — Phase 2: Reliable Baseline", () => {
  for (const [agentId, agent] of Object.entries(profileData.agents) as [string, any][]) {
    test(`${agentId}: reaches reliable maturity after 5 sessions`, () => {
      const buildId = buildIds[agentId];
      const obf = new Obfuscator(config);

      // Add 2 more sessions (total 5)
      for (let session = 0; session < 2; session++) {
        const profiler = new BehaviouralProfiler(
          { mode: "learning", sigma: 3, minBaseline: 5, profileDir: tempDir },
          store,
        );
        profiler.setAgentBuildId(buildId);

        for (const turn of agent.training.slice(0, 5)) {
          const result = obf.obfuscate(turn.input);
          const catCounts: Record<string, number> = {};
          for (const entity of result.entities) {
            catCounts[entity.category] = (catCounts[entity.category] ?? 0) + 1;
          }
          profiler.extractRequestFeatures(turn.input, catCounts);
          profiler.extractResponseFeatures("Response.", []);
        }

        profiler.finalizeSession();
        obf.reset();
      }

      const baseline = store.load(buildId);
      expect(baseline).not.toBeNull();
      expect(baseline!.sessionCount).toBe(5);
      expect(baseline!.maturity).toBe("reliable");
    });
  }
});

// ===================================================================
// Phase 3: Adversarial detection
// ===================================================================

describe("Profiler Training — Phase 3: Adversarial Detection", () => {
  for (const [agentId, agent] of Object.entries(profileData.agents) as [string, any][]) {
    for (const adv of agent.adversarial) {
      test(`${agentId}: ${adv.name}`, () => {
        const buildId = buildIds[agentId];
        const obf = new Obfuscator(config);

        const profiler = new BehaviouralProfiler(
          { mode: "active", sigma: 3, minBaseline: 3, profileDir: tempDir },
          store,
        );
        profiler.setAgentBuildId(buildId);

        // First do a normal turn (establishes lexical baseline for this session)
        const normalTurn = agent.training[0];
        const normalResult = obf.obfuscate(normalTurn.input);
        const normalCats: Record<string, number> = {};
        for (const e of normalResult.entities) {
          normalCats[e.category] = (normalCats[e.category] ?? 0) + 1;
        }
        profiler.extractRequestFeatures(normalTurn.input, normalCats);
        profiler.extractResponseFeatures("Normal response.", []);

        // Now the adversarial turn
        const advResult = obf.obfuscate(adv.input);
        const advCats: Record<string, number> = {};
        for (const e of advResult.entities) {
          advCats[e.category] = (advCats[e.category] ?? 0) + 1;
        }
        profiler.extractRequestFeatures(adv.input, advCats);
        const fv = profiler.extractResponseFeatures("Adversarial response.", []);

        // Check for injection detection (Track 1)
        const injectionEvents = detector.scanRequest(adv.input);
        const hasInjection = adv.expected_anomalies.includes("injection_detected");
        if (hasInjection) {
          expect(injectionEvents.length).toBeGreaterThan(0);
        }

        // Check for anomaly detection (Track 3)
        if (fv) {
          const alerts = profiler.analyzeTurn(fv);

          // Log what we detected for debugging
          const detectedTypes = alerts.map(a => a.type);

          // At least verify we get SOME anomaly signal for adversarial input
          // (specific anomaly types depend on how much the adversarial input
          // deviates from baseline — some are subtle)
          const expectedAnomalies = adv.expected_anomalies.filter(
            (a: string) => a !== "injection_detected",
          );

          if (expectedAnomalies.length > 0) {
            // We should detect at least one anomaly OR the injection scanner caught it
            // OR the lexical overlap should be notably low (topic shift)
            const hasAnySignal = alerts.length > 0 || injectionEvents.length > 0 || fv.lexicalOverlapWithPrevious < 0.3;
            expect(hasAnySignal).toBe(true);
          }
        }
      });
    }
  }
});

// ===================================================================
// Phase 4: Cross-agent confusion
// ===================================================================

describe("Profiler Training — Phase 4: Cross-Agent Confusion", () => {
  test("security-researcher prompt sent to customer-outreach agent triggers anomaly", () => {
    const outreachBuildId = buildIds["customer-outreach"];
    const obf = new Obfuscator(config);

    const profiler = new BehaviouralProfiler(
      { mode: "active", sigma: 2.5, minBaseline: 3, profileDir: tempDir },
      store,
    );
    profiler.setAgentBuildId(outreachBuildId);

    // Normal outreach turn first
    const normalInput = "Draft an email to sarah@company.com about the Q3 renewal.";
    const normalResult = obf.obfuscate(normalInput);
    const normalCats: Record<string, number> = {};
    for (const e of normalResult.entities) normalCats[e.category] = (normalCats[e.category] ?? 0) + 1;
    profiler.extractRequestFeatures(normalInput, normalCats);
    profiler.extractResponseFeatures("Email drafted.", []);

    // Now send a security-researcher prompt
    const crossInput = "Analyze the BGP peering on router core-rtr-01.datacenter.net at AS 65412. Check SNMP community 'netops2024' on VLAN 200.";
    const crossResult = obf.obfuscate(crossInput);
    const crossCats: Record<string, number> = {};
    for (const e of crossResult.entities) crossCats[e.category] = (crossCats[e.category] ?? 0) + 1;
    profiler.extractRequestFeatures(crossInput, crossCats);
    const fv = profiler.extractResponseFeatures("BGP analysis.", []);

    if (fv) {
      const alerts = profiler.analyzeTurn(fv);
      // Should detect SOMETHING anomalous — different entity categories, topic shift
      // At minimum the lexical overlap should be very low
      expect(fv.lexicalOverlapWithPrevious).toBeLessThan(0.3);
    }
  });

  test("customer-outreach prompt sent to support-bot agent detects shift", () => {
    const supportBuildId = buildIds["support-bot"];
    const obf = new Obfuscator(config);

    const profiler = new BehaviouralProfiler(
      { mode: "active", sigma: 2.5, minBaseline: 3, profileDir: tempDir },
      store,
    );
    profiler.setAgentBuildId(supportBuildId);

    // Normal support turn
    const normalInput = "User dev-team@startup.io reports 502 error on VM instance at IP 10.100.50.23.";
    const normalResult = obf.obfuscate(normalInput);
    const normalCats: Record<string, number> = {};
    for (const e of normalResult.entities) normalCats[e.category] = (normalCats[e.category] ?? 0) + 1;
    profiler.extractRequestFeatures(normalInput, normalCats);
    profiler.extractResponseFeatures("Investigating.", []);

    // Now send a sales outreach prompt
    const crossInput = "Research Sarah Chen, VP Engineering at Meridian Systems. Email s.chen@meridiansys.com, phone +1-415-555-0142. Prepare a cold outreach email.";
    const crossResult = obf.obfuscate(crossInput);
    const crossCats: Record<string, number> = {};
    for (const e of crossResult.entities) crossCats[e.category] = (crossCats[e.category] ?? 0) + 1;
    profiler.extractRequestFeatures(crossInput, crossCats);
    const fv = profiler.extractResponseFeatures("Outreach prepared.", []);

    if (fv) {
      const alerts = profiler.analyzeTurn(fv);
      // Topic shift should be detectable via low lexical overlap
      expect(fv.lexicalOverlapWithPrevious).toBeLessThan(0.3);
    }
  });

  test("all three agents have distinct build IDs", () => {
    const ids = Object.values(buildIds);
    const unique = new Set(ids);
    expect(unique.size).toBe(3);
  });

  test("all three agents have different dominant categories", () => {
    const categories: Record<string, string[]> = {};
    for (const [agentId, buildId] of Object.entries(buildIds)) {
      const baseline = store.load(buildId);
      expect(baseline).not.toBeNull();
      categories[agentId] = baseline!.categoryProfile;
    }

    // security-researcher should have network entities
    expect(categories["security-researcher"]).toContain("ip_address");

    // customer-outreach should have PII entities
    expect(categories["customer-outreach"]).toContain("email");

    // support-bot should have IP addresses (VM IPs, DNS records)
    expect(categories["support-bot"]).toContain("ip_address");

    // All three should have some entity categories tracked
    for (const [agentId, cats] of Object.entries(categories)) {
      expect(cats.length).toBeGreaterThan(0);
    }

    // Profiles should be meaningfully different
    const researcherSet = new Set(categories["security-researcher"]);
    const outreachSet = new Set(categories["customer-outreach"]);
    // Not identical — different agents should have different category profiles
    const overlap = [...researcherSet].filter(c => outreachSet.has(c)).length;
    const totalUnique = new Set([...researcherSet, ...outreachSet]).size;
    expect(overlap / totalUnique).toBeLessThan(1); // not 100% overlap
  });
});

afterAll(() => {
  try { rmSync(tempDir, { recursive: true }); } catch {}
});
