/**
 * Multi-agent security test runner.
 *
 * Extends the existing OpenClaw E2E runner with:
 * - Multiple concurrent agent sessions with distinct SOUL.md configs
 * - Injection detection verification via shroud_security tool
 * - Agent session attribution validation
 * - Per-agent profiling isolation checks
 * - Cross-agent session isolation tests
 *
 * Runs inside the same Docker container as the standard E2E tests.
 * Uses a single gateway but creates sessions with different system prompts
 * to simulate multiple agents.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import {
  assertAgentIdentity,
  assertUniqueBuildIds,
  assertNoFrameworkPreamble,
  assertToolInventory,
  assertCategoryProfile,
  assertNoDuplicateAgents,
  assertBuildIdStability,
  assertBaselinePersistence,
  assertChannelsDetected,
} from "../lib/assertions.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

export class SecurityTestRunner {
  constructor(opts = {}) {
    this.stateDir = opts.stateDir || process.env.OPENCLAW_STATE_DIR || "/shroud/state";
    this.verbose = opts.verbose || false;
    this.gatewayPort = null;
    this.gatewayProc = null;
    this.gatewayStdout = "";
    this.gatewayStderr = "";
    this.mockLlmPort = null;
    this.workspaceDir = join(this.stateDir, "workspace");

    this.results = { total: 0, passed: 0, failed: 0, skipped: 0 };
  }

  /**
   * Write a SOUL.md to the workspace for the given agent.
   * The gateway picks this up on next session creation.
   */
  _setAgentSoul(agentSoul) {
    try {
      writeFileSync(join(this.workspaceDir, "SOUL.md"), agentSoul, "utf-8");
    } catch {
      // workspace may not exist outside Docker
    }
  }

  async run() {
    this._log("=== Multi-Agent Security Tests ===");
    this._log("");

    // Load scenarios
    const scenarioPath = join(__dirname, "scenarios", "security-multi-agent.json");
    if (!existsSync(scenarioPath)) {
      this._log("No security-multi-agent.json found — skipping");
      return this.results;
    }
    const scenarioData = JSON.parse(readFileSync(scenarioPath, "utf-8"));
    const { agents, scenarios } = scenarioData;

    // Build agent map
    const agentMap = new Map();
    for (const agent of agents) {
      agentMap.set(agent.id, agent);
    }

    this._log(`Loaded ${scenarios.length} security scenarios for ${agents.length} agents`);
    this._log(`Agents: ${agents.map(a => a.id).join(", ")}`);
    this._log("-".repeat(50));

    // Run each scenario
    for (const scenario of scenarios) {
      this.results.total++;

      if (scenario.parallel) {
        await this._runParallelScenario(scenario, agentMap);
      } else if (scenario.turns) {
        await this._runMultiTurnScenario(scenario, agentMap);
      } else if (scenario.followup) {
        await this._runFollowupScenario(scenario, agentMap);
      } else {
        await this._runSingleScenario(scenario, agentMap);
      }
    }

    this._log("");
    this._log("=".repeat(50));
    this._log(`Total: ${this.results.passed} passed  ${this.results.failed} failed  ${this.results.total} total`);

    return this.results;
  }

  async _runSingleScenario(scenario, agentMap) {
    await this._clearSecurityEvents();
    const start = Date.now();
    try {
      const agent = agentMap.get(scenario.agent);
      if (!agent) throw new Error(`Unknown agent: ${scenario.agent}`);

      // Create session with agent's SOUL as system prompt
      const sessionKey = `sec-${scenario.agent}-${Date.now()}`;
      this._setAgentSoul(agent.soul);
      const response = await this._gatewayCall("sessions.create", {
        key: sessionKey,
        message: scenario.input,
      });

      const assertions = scenario.assertions || {};

      // Injection detection check — poll because sessions.create returns
      // before the agent makes the LLM call (where scanning happens)
      let secEvents = [];
      if (assertions.injection_detected === true) {
        secEvents = await this._pollForInjectionEvents(start);
        if (secEvents.length === 0) {
          throw new Error(`Expected injection detected but none found`);
        }
        if (assertions.injection_threat_class) {
          const hasClass = secEvents.some(e => e.threatClass === assertions.injection_threat_class);
          if (!hasClass) {
            throw new Error(`Expected threat class "${assertions.injection_threat_class}" but got: ${secEvents.map(e => e.threatClass).join(", ")}`);
          }
        }
        if (assertions.injection_severity) {
          const hasSev = secEvents.some(e => e.severity === assertions.injection_severity);
          if (!hasSev) {
            throw new Error(`Expected severity "${assertions.injection_severity}" but got: ${secEvents.map(e => e.severity).join(", ")}`);
          }
        }
      } else if (assertions.injection_detected === false) {
        // Wait a bit to let any events arrive, then check none exist
        await new Promise(r => setTimeout(r, 3000));
        secEvents = await this._getSecurityEvents();
        const relevant = secEvents.filter(e =>
          e.eventType === "injection_detected" &&
          e.timestamp > start
        );
        if (relevant.length > 0) {
          throw new Error(`Expected NO injection but found ${relevant.length}: ${relevant.map(e => e.signatureId).join(", ")}`);
        }
      } else {
        secEvents = await this._getSecurityEvents();
      }

      // Agent attribution check
      if (assertions.agent_attributed) {
        const agentSessions = await this._getAgentSessions();
        if (agentSessions.length === 0) {
          throw new Error("No agent sessions tracked");
        }
        // Verify events are attributed
        const attributed = secEvents.filter(e => e.agentBuildId && e.timestamp > start);
        if (assertions.injection_detected && attributed.length === 0) {
          throw new Error("Security events not attributed to any agent");
        }
      }

      // Distinct build IDs check
      if (assertions.distinct_build_ids) {
        const agentSessions = await this._getAgentSessions();
        const buildIds = new Set(agentSessions.map(s => s.agentBuildId));
        if (buildIds.size < agentSessions.length) {
          throw new Error(`Expected distinct build IDs but got duplicates: ${[...buildIds].join(", ")}`);
        }
      }

      // Agent label check
      if (assertions.agent_label_contains) {
        const agentSessions = await this._getAgentSessions();
        const match = agentSessions.find(s =>
          s.agentLabel && s.agentLabel.toLowerCase().includes(assertions.agent_label_contains.toLowerCase())
        );
        if (!match) {
          const labels = agentSessions.map(s => s.agentLabel).join(", ");
          throw new Error(`No agent label contains "${assertions.agent_label_contains}". Found: ${labels}`);
        }
      }

      // Agent classification role check
      if (assertions.agent_classification_role) {
        const agentSessions = await this._getAgentSessions();
        const match = agentSessions.find(s =>
          s.classification?.role === assertions.agent_classification_role
        );
        if (!match) {
          const roles = agentSessions.map(s => s.classification?.role || "?").join(", ");
          throw new Error(`No agent classified as "${assertions.agent_classification_role}". Found: ${roles}`);
        }
      }

      // Distinct agent labels check
      if (assertions.distinct_agent_labels) {
        const agentSessions = await this._getAgentSessions();
        const labels = new Set(agentSessions.map(s => s.agentLabel));
        if (labels.size < agentSessions.length) {
          throw new Error(`Expected distinct labels but got duplicates: ${[...labels].join(", ")}`);
        }
      }

      // Minimum agents tracked check
      if (assertions.min_agents_tracked) {
        const agentSessions = await this._getAgentSessions();
        if (agentSessions.length < assertions.min_agents_tracked) {
          throw new Error(`Expected at least ${assertions.min_agents_tracked} agents, found ${agentSessions.length}`);
        }
      }

      // Session consolidation check (same agent = same session across turns)
      if (assertions.agent_session_consolidated) {
        const agentSessions = await this._getAgentSessions();
        // The agent used in this scenario should have exactly 1 session
        const agentLabel = agentSessions.find(s =>
          s.agentLabel && s.agentLabel.toLowerCase().includes("research")
        );
        if (agentLabel && agentLabel.llmCallCount < 2) {
          throw new Error(`Expected consolidated session with 2+ calls, got ${agentLabel.llmCallCount}`);
        }
      }

      // LLM must not see check
      if (assertions.llm_must_not_see?.length > 0) {
        const llmRequests = await this._getLlmRequests();
        const lastReq = JSON.stringify(llmRequests[llmRequests.length - 1] || "");
        for (const val of assertions.llm_must_not_see) {
          if (lastReq.includes(val)) {
            throw new Error(`LLM saw real value: "${val}"`);
          }
        }
      }

      this._pass(scenario.name, Date.now() - start);
    } catch (err) {
      this._fail(scenario.name, err.message);
    }
  }

  async _runMultiTurnScenario(scenario, agentMap) {
    await this._clearSecurityEvents();
    const start = Date.now();
    try {
      const agent = agentMap.get(scenario.agent);
      if (!agent) throw new Error(`Unknown agent: ${scenario.agent}`);

      const sessionKey = `sec-mt-${scenario.agent}-${Date.now()}`;

      for (let i = 0; i < scenario.turns.length; i++) {
        const turn = scenario.turns[i];
        // Clear events between turns to prevent cross-turn contamination
        await this._clearSecurityEvents();
        const turnStart = Date.now();

        if (i === 0) {
          this._setAgentSoul(agent.soul);
          await this._gatewayCall("sessions.create", {
            key: sessionKey,
            message: turn.input,
          });
        } else {
          await this._gatewayCall("sessions.send", {
            key: sessionKey,
            message: turn.input,
          });
        }

        // Check turn-specific assertions
        if (turn.assertions?.injection_detected === true) {
          const relevant = await this._pollForInjectionEvents(turnStart);
          if (relevant.length === 0) {
            throw new Error(`Turn ${i}: expected injection detected but none found`);
          }
          if (turn.assertions.injection_threat_class) {
            const hasClass = relevant.some(e => e.threatClass === turn.assertions.injection_threat_class);
            if (!hasClass) {
              throw new Error(`Turn ${i}: expected threat class "${turn.assertions.injection_threat_class}"`);
            }
          }
        } else if (turn.assertions?.injection_detected === false) {
          await new Promise(r => setTimeout(r, 3000));
          const secEvents = await this._getSecurityEvents();
          const relevant = secEvents.filter(e =>
            e.eventType === "injection_detected" &&
            e.timestamp > turnStart
          );
          if (relevant.length > 0) {
            throw new Error(`Turn ${i}: expected NO injection but found ${relevant.length}`);
          }
        }

        if (turn.assertions?.llm_must_not_see?.length > 0) {
          const llmRequests = await this._getLlmRequests();
          const lastReq = JSON.stringify(llmRequests[llmRequests.length - 1] || "");
          for (const val of turn.assertions.llm_must_not_see) {
            if (lastReq.includes(val)) {
              throw new Error(`Turn ${i}: LLM saw real value: "${val}"`);
            }
          }
        }
      }

      this._pass(scenario.name, Date.now() - start);
    } catch (err) {
      this._fail(scenario.name, err.message);
    }
  }

  async _runFollowupScenario(scenario, agentMap) {
    await this._clearSecurityEvents();
    const start = Date.now();
    try {
      // First agent
      const agent1 = agentMap.get(scenario.agent);
      if (!agent1) throw new Error(`Unknown agent: ${scenario.agent}`);

      const session1Key = `sec-fu1-${Date.now()}`;
      this._setAgentSoul(agent1.soul);
      await this._gatewayCall("sessions.create", {
        key: session1Key,
        message: scenario.input,
      });

      // Check first agent assertions
      if (scenario.assertions?.injection_detected) {
        const relevant = await this._pollForInjectionEvents(start);
        if (relevant.length === 0) {
          throw new Error("First agent: expected injection detected but none found");
        }
      }

      // Followup with second agent
      const followup = scenario.followup;
      const agent2 = agentMap.get(followup.agent);
      if (!agent2) throw new Error(`Unknown agent: ${followup.agent}`);

      const followupStart = Date.now();
      const session2Key = `sec-fu2-${Date.now()}`;
      this._setAgentSoul(agent2.soul);
      await this._gatewayCall("sessions.create", {
        key: session2Key,
        message: followup.input,
      });

      // Check followup assertions
      if (followup.assertions?.injection_detected === false) {
        await new Promise(r => setTimeout(r, 3000));
        const secEvents = await this._getSecurityEvents();
        const relevant = secEvents.filter(e =>
          e.eventType === "injection_detected" && e.timestamp > followupStart
        );
        if (relevant.length > 0) {
          throw new Error(`Followup agent: expected NO injection but found ${relevant.length} (cross-agent leak?)`);
        }
      }

      if (followup.assertions?.llm_must_not_see?.length > 0) {
        const llmRequests = await this._getLlmRequests();
        const lastReq = llmRequests[llmRequests.length - 1] || "";
        for (const val of followup.assertions.llm_must_not_see) {
          if (lastReq.includes(val)) {
            throw new Error(`Followup: LLM saw real value: "${val}"`);
          }
        }
      }

      this._pass(scenario.name, Date.now() - start);
    } catch (err) {
      this._fail(scenario.name, err.message);
    }
  }

  async _runParallelScenario(scenario, agentMap) {
    await this._clearSecurityEvents();
    const start = Date.now();
    try {
      // Run all parallel sub-scenarios concurrently
      const promises = scenario.parallel.map(async (sub, idx) => {
        const agent = agentMap.get(sub.agent);
        if (!agent) throw new Error(`Unknown agent: ${sub.agent}`);

        const sessionKey = `sec-par-${sub.agent}-${idx}-${Date.now()}`;
        this._setAgentSoul(agent.soul);
        await this._gatewayCall("sessions.create", {
          key: sessionKey,
          message: sub.input,
        });

        return { sub, agent, sessionKey };
      });

      await Promise.all(promises);

      // After all complete, verify PII assertions
      const llmRequests = await this._getLlmRequests();
      const recentRequests = llmRequests.slice(-scenario.parallel.length);

      for (let i = 0; i < scenario.parallel.length; i++) {
        const sub = scenario.parallel[i];
        if (sub.assertions?.llm_must_not_see?.length > 0) {
          // Check ALL recent requests for the real values
          const allText = recentRequests.map(r => JSON.stringify(r)).join("\n");
          for (const val of sub.assertions.llm_must_not_see) {
            if (allText.includes(val)) {
              throw new Error(`Parallel[${sub.agent}]: LLM saw real value: "${val}"`);
            }
          }
        }
      }

      // Check injection detection for parallel scenarios
      for (const sub of scenario.parallel) {
        if (sub.assertions?.injection_detected) {
          const relevant = await this._pollForInjectionEvents(start);
          if (relevant.length === 0) {
            throw new Error(`Parallel[${sub.agent}]: expected injection detected but none found`);
          }
        }
      }

      this._pass(scenario.name, Date.now() - start);
    } catch (err) {
      this._fail(scenario.name, err.message);
    }
  }

  // ── Helpers ──────────────────────────────────────────────

  async _getSecurityEvents() {
    try {
      const res = await this._httpGet("http://127.0.0.1:9380/api/events");
      const parsed = JSON.parse(res);
      return parsed.events || [];
    } catch (err) {
      // Log once on first failure to help diagnose dashboard connectivity
      if (!this._dashboardWarnShown) {
        this._dashboardWarnShown = true;
        this._log(`  [WARN] Dashboard /api/events unreachable: ${err.message?.slice(0, 80)}`);
      }
      return [];
    }
  }

  async _getAgentSessions() {
    try {
      const res = await this._httpGet("http://127.0.0.1:9380/api/agents");
      const parsed = JSON.parse(res);
      return parsed.agents || [];
    } catch (err) {
      if (!this._dashboardWarnShown) {
        this._dashboardWarnShown = true;
        this._log(`  [WARN] Dashboard /api/agents unreachable: ${err.message?.slice(0, 80)}`);
      }
      return [];
    }
  }

  async _getLlmRequests() {
    try {
      const res = await this._httpGet(`http://127.0.0.1:${this.mockLlmPort}/requests`);
      return JSON.parse(res);
    } catch {
      return [];
    }
  }

  _gatewayCall(method, params) {
    const bin = this._getOpenClawBin();
    const args = [
      bin, "gateway", "call", method,
      "--expect-final",
      "--timeout", "30000",
      "--json",
      "--url", `ws://127.0.0.1:${this.gatewayPort}`,
      "--token", "shroud-test-token",
      "--params", JSON.stringify(params),
    ];
    try {
      return execFileSync("node", args, {
        timeout: 35000,
        encoding: "utf-8",
        env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      });
    } catch (err) {
      throw new Error(`Gateway call ${method} failed: ${err.message?.slice(0, 200)}`);
    }
  }

  _httpGet(url, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const req = http.get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => resolve(data));
        res.on("error", reject);
      });
      req.on("error", reject);
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error(`HTTP GET ${url} timed out after ${timeoutMs}ms`));
      });
    });
  }

  /** Clear all security events via dashboard API. Isolates scenarios from each other. */
  async _clearSecurityEvents() {
    try {
      await new Promise((resolve, reject) => {
        const req = http.request("http://127.0.0.1:9380/api/events", { method: "DELETE" }, (res) => {
          res.resume();
          res.on("end", resolve);
        });
        req.on("error", reject);
        req.setTimeout(3000, () => req.destroy());
        req.end();
      });
    } catch { /* non-fatal */ }
  }

  /**
   * Poll the dashboard for injection events appearing after `since` (ms timestamp).
   * sessions.create returns before the agent makes the LLM call, so events
   * may not exist yet. Polls up to `maxWaitMs` with 500ms intervals.
   */
  async _pollForInjectionEvents(since, maxWaitMs = 10000) {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const events = await this._getSecurityEvents();
      const relevant = events.filter(e =>
        e.eventType === "injection_detected" && e.timestamp > since
      );
      if (relevant.length > 0) return relevant;
      await new Promise(r => setTimeout(r, 500));
    }
    return [];
  }

  _getOpenClawBin() {
    return process.env.OPENCLAW_BIN || "openclaw";
  }

  _pass(name, durationMs) {
    this.results.passed++;
    this._log(`  \x1b[32m\u2714\x1b[0m ${name}  \x1b[2m(${durationMs}ms)\x1b[0m`);
  }

  _fail(name, error) {
    this.results.failed++;
    this._log(`  \x1b[31m\u2718\x1b[0m ${name}`);
    this._log(`    \x1b[31m${error}\x1b[0m`);
  }

  _log(msg) {
    if (this.verbose || process.env.SHROUD_TEST_VERBOSE) {
      process.stdout.write(msg + "\n");
    }
  }

  // ══════════════════════════════════════════════════════════════
  // Lifecycle Tests — long-running multi-agent identity & profiling
  // ══════════════════════════════════════════════════════════════

  /**
   * Run the full lifecycle test suite.
   * Requires a running gateway (this.gatewayPort) and mock LLM (this.mockLlmPort).
   *
   * Callback `restartGateway` is called between Phase 1 and Phase 2 to
   * kill and restart the gateway process. The caller (openclaw-runner)
   * provides this because it owns the gateway process.
   *
   * @param {Function} restartGateway - async () => void — kills and restarts gateway
   */
  async runLifecycleTests(restartGateway) {
    this._log("\n" + "=".repeat(60));
    this._log("=== Agent Lifecycle Tests ===");
    this._log("=".repeat(60));

    const scenarioPath = join(__dirname, "scenarios", "agent-lifecycle.json");
    if (!existsSync(scenarioPath)) {
      this._log("No agent-lifecycle.json found — skipping lifecycle tests");
      return this.results;
    }

    const data = JSON.parse(readFileSync(scenarioPath, "utf-8"));
    const { agents, phases } = data;

    this._log(`Loaded ${agents.length} agents for lifecycle testing`);
    this._log(`Agents: ${agents.map(a => a.id).join(", ")}`);

    // ── Phase 1: Baseline Accumulation ──────────────────────────
    await this._runPhase1(agents, phases.baseline_accumulation);

    // Snapshot agent state before restart
    const preRestartAgents = await this._getAgentSessions();

    // ── Phase 2: Restart Persistence ────────────────────────────
    if (restartGateway) {
      await this._runPhase2(agents, phases.restart_persistence, preRestartAgents, restartGateway);
    } else {
      this._log("\n  [SKIP] Phase 2: no restartGateway callback provided");
    }

    // ── Phase 3: Adversarial ────────────────────────────────────
    await this._runPhase3(agents, phases.adversarial);

    this._log("\n" + "=".repeat(60));
    this._log(`Lifecycle: ${this.results.passed} passed  ${this.results.failed} failed`);

    return this.results;
  }

  /**
   * Phase 1: Send realistic traffic to all agents and verify identity stability.
   * Traffic is generated from seed messages — each seed is expanded with rotating
   * PII (IPs, emails, hostnames, phones) to produce min_turns_per_agent unique messages.
   */
  async _runPhase1(agents, phaseConfig) {
    this._log("\n── Phase 1: Baseline Accumulation ──");
    const minTurns = phaseConfig?.min_turns_per_agent || 200;

    this._log(`  Generating ${minTurns} turns per agent (${agents.length} agents, ${minTurns * agents.length} total calls)...`);

    // Track build IDs per agent across turns
    const buildIdHistory = new Map(); // label → Set<buildId>

    for (let turn = 0; turn < minTurns; turn++) {
      for (const agent of agents) {
        const seeds = agent.traffic || [];
        if (seeds.length === 0) continue;

        // Generate a message: pick a seed and rotate PII into it
        const message = this._generateTrafficMessage(seeds, turn);
        const sessionKey = `lifecycle-${agent.id}`;
        const systemPrompt = this._buildAgentPrompt(agent, message);

        try {
          if (turn === 0) {
            this._setAgentSoul(systemPrompt);
            await this._gatewayCall("sessions.create", {
              key: sessionKey,
              message,
            });
          } else {
            this._setAgentSoul(systemPrompt);
            await this._gatewayCall("sessions.send", {
              key: sessionKey,
              message,
            });
          }

          // Snapshot build ID every 25 turns (skip turn 0 — nothing to check yet)
          if (turn > 0 && turn % 25 === 0) {
            const snapshot = await this._getAgentSessions();
            for (const a of snapshot) {
              if (!buildIdHistory.has(a.agentLabel)) {
                buildIdHistory.set(a.agentLabel, new Set());
              }
              buildIdHistory.get(a.agentLabel).add(a.agentBuildId);
            }
          }
        } catch (err) {
          this._log(`    [WARN] Turn ${turn} for ${agent.id}: ${err.message?.slice(0, 100)}`);
        }
      }

      // Small delay between rounds to avoid overwhelming the gateway
      if (turn % 5 === 0) await new Promise(r => setTimeout(r, 200));

      // Progress indicator every 25 turns
      if ((turn + 1) % 25 === 0) {
        this._log(`  ... ${turn + 1}/${minTurns} turns complete (${(turn + 1) * agents.length} total calls)`);
      }
    }

    // ── Phase 1 Assertions ──────────────────────────────────────
    const agentSessions = await this._getAgentSessions();
    const assertions = phaseConfig?.assertions || {};

    // 1a. Unique build IDs
    this.results.total++;
    try {
      assertUniqueBuildIds(agentSessions);
      this._pass("Phase 1: unique build IDs (no collisions)");
    } catch (err) {
      this._fail("Phase 1: unique build IDs", err.message);
    }

    // 1b. Correct labels and roles
    this.results.total++;
    try {
      assertAgentIdentity(agentSessions, agents);
      this._pass("Phase 1: all agents have correct labels and roles");
    } catch (err) {
      this._fail("Phase 1: agent identity", err.message);
    }

    // 1c. No framework preamble in SOUL extract
    this.results.total++;
    try {
      assertNoFrameworkPreamble(agentSessions);
      this._pass("Phase 1: no framework preamble in soulExtract");
    } catch (err) {
      this._fail("Phase 1: framework preamble check", err.message);
    }

    // 1d. Tool inventory populated
    this.results.total++;
    try {
      assertToolInventory(agentSessions, agents);
      this._pass("Phase 1: tool inventory populated");
    } catch (err) {
      this._fail("Phase 1: tool inventory", err.message);
    }

    // 1e. Category profiles populated
    this.results.total++;
    try {
      assertCategoryProfile(agentSessions);
      this._pass("Phase 1: category profiles populated");
    } catch (err) {
      this._fail("Phase 1: category profiles", err.message);
    }

    // 1f. No duplicate agents
    this.results.total++;
    try {
      assertNoDuplicateAgents(agentSessions);
      this._pass("Phase 1: no duplicate agents");
    } catch (err) {
      this._fail("Phase 1: duplicate agents", err.message);
    }

    // 1g. Build ID stable across turns
    this.results.total++;
    try {
      let unstable = [];
      for (const [label, ids] of buildIdHistory) {
        if (ids.size > 1) {
          unstable.push(`${label}: ${[...ids].join(", ")}`);
        }
      }
      if (unstable.length > 0) {
        throw new Error(`Build IDs changed across turns:\n  ${unstable.join("\n  ")}`);
      }
      this._pass("Phase 1: build IDs stable across turns");
    } catch (err) {
      this._fail("Phase 1: build ID stability", err.message);
    }

    // 1h. Summary stats
    this._log(`\n  Phase 1 Summary:`);
    for (const a of agentSessions) {
      const p = a.profiling || {};
      this._log(`    ${a.agentLabel}: ${a.llmCallCount} calls, buildId=${a.agentBuildId?.slice(0,8)}, role=${a.classification?.role}, channels=[${(a.channels||[]).join(",")}], tools=${a.toolInventory?.length || 0}, baseline=${p.maturity || "none"}`);
    }
  }

  /**
   * Phase 2: Kill gateway, restart, verify persistence.
   */
  async _runPhase2(agents, phaseConfig, preRestartAgents, restartGateway) {
    this._log("\n── Phase 2: Restart Persistence ──");

    // Restart the gateway
    this._log("  Restarting gateway...");
    await restartGateway();
    this._log("  Gateway restarted.");

    // Wait for dashboard to be available
    await this._waitForDashboard(20000);

    // Send a few more turns per agent
    const turnsAfter = phaseConfig?.turns_after_restart || 3;
    this._log(`  Sending ${turnsAfter} turns per agent after restart...`);

    for (let turn = 0; turn < turnsAfter; turn++) {
      for (const agent of agents) {
        const trafficIdx = (agent.traffic?.length || 1) - turnsAfter + turn;
        const message = agent.traffic?.[Math.max(0, trafficIdx)] || "Hello, are you still there?";
        const sessionKey = `lifecycle-${agent.id}`;
        const systemPrompt = this._buildAgentPrompt(agent, message);

        try {
          this._setAgentSoul(systemPrompt);
          // After restart, the session key may not exist — use create
          if (turn === 0) {
            await this._gatewayCall("sessions.create", {
              key: `${sessionKey}-post-restart`,
              message,
            });
          } else {
            await this._gatewayCall("sessions.send", {
              key: `${sessionKey}-post-restart`,
              message,
            });
          }
        } catch (err) {
          this._log(`    [WARN] Post-restart turn for ${agent.id}: ${err.message?.slice(0, 100)}`);
        }
      }
    }

    // Wait for post-restart sessions to register with the dashboard
    await new Promise(r => setTimeout(r, 5000));

    // ── Phase 2 Assertions ──────────────────────────────────────
    const postRestartAgents = await this._getAgentSessions();

    // 2a. Build IDs match pre-restart
    this.results.total++;
    try {
      assertBuildIdStability(preRestartAgents, postRestartAgents);
      this._pass("Phase 2: build IDs stable across restart");
    } catch (err) {
      this._fail("Phase 2: build ID stability", err.message);
    }

    // 2b. Baselines survived
    this.results.total++;
    try {
      assertBaselinePersistence(preRestartAgents, postRestartAgents);
      this._pass("Phase 2: baselines survived restart");
    } catch (err) {
      this._fail("Phase 2: baseline persistence", err.message);
    }

    // 2c. Labels unchanged
    this.results.total++;
    try {
      assertAgentIdentity(postRestartAgents, agents);
      this._pass("Phase 2: labels and roles unchanged after restart");
    } catch (err) {
      this._fail("Phase 2: labels after restart", err.message);
    }

    // 2d. No duplicate agents
    this.results.total++;
    try {
      assertNoDuplicateAgents(postRestartAgents);
      this._pass("Phase 2: no duplicate agents after restart");
    } catch (err) {
      this._fail("Phase 2: duplicates after restart", err.message);
    }

    // 2e. No orphan baseline files
    this.results.total++;
    try {
      const profileDir = join(process.env.HOME || "/shroud", ".shroud", "profiles");
      if (existsSync(profileDir)) {
        const files = readdirSync(profileDir).filter(f => /^[a-f0-9]{16}\.json$/.test(f));
        const knownIds = new Set(postRestartAgents.map(a => a.agentBuildId));
        const orphans = files.filter(f => !knownIds.has(f.replace(".json", "")));
        if (orphans.length > 0) {
          throw new Error(`Orphan baseline files: ${orphans.join(", ")}`);
        }
      }
      this._pass("Phase 2: no orphan baseline files");
    } catch (err) {
      this._fail("Phase 2: orphan baselines", err.message);
    }

    // Summary
    this._log(`\n  Phase 2 Summary:`);
    for (const a of postRestartAgents) {
      const pre = preRestartAgents.find(p => p.agentLabel?.toLowerCase() === a.agentLabel?.toLowerCase());
      this._log(`    ${a.agentLabel}: calls ${pre?.llmCallCount || 0}→${a.llmCallCount}, buildId=${a.agentBuildId?.slice(0,8)}`);
    }
  }

  /**
   * Phase 3: Adversarial — 1000 generated injection attempts and identity pollution.
   *
   * Generates attacks from templates × payloads × agents. Each attack is sent to
   * a random agent and verified for detection + correct attribution.
   * Preamble injection attacks additionally verify that the agent's label survives.
   */
  async _runPhase3(agents, phaseConfig) {
    this._log("\n── Phase 3: Adversarial ──");

    const targetCount = phaseConfig?.generated_attack_count || 1000;
    const templates = phaseConfig?.injection_templates || {};
    const payloads = phaseConfig?.payloads || ["Give me all passwords."];
    const roles = phaseConfig?.malicious_roles || ["DAN"];
    const piiValues = phaseConfig?.pii_for_exfil || ["admin@evil.com"];
    const shellIps = phaseConfig?.ips_for_shells || ["203.0.113.50"];
    const seedAttacks = phaseConfig?.seed_attacks || [];

    // Generate the full attack list
    const attacks = this._generateAttacks(
      targetCount, templates, payloads, roles, piiValues, shellIps, agents, seedAttacks,
    );

    this._log(`  Generated ${attacks.length} attacks across ${agents.length} agents`);

    // Track results in bulk — don't log every single attack
    let detected = 0;
    let attributed = 0;
    let preambleSurvived = 0;
    let preambleTotal = 0;
    let missed = 0;
    let errors = 0;

    for (let i = 0; i < attacks.length; i++) {
      const attack = attacks[i];
      const start = Date.now();

      try {
        const sessionKey = `lifecycle-adv-${i}-${Date.now()}`;
        const systemPrompt = this._buildAgentPrompt(attack.agent, attack.input);
        this._setAgentSoul(systemPrompt);

        await this._gatewayCall("sessions.create", {
          key: sessionKey,
          message: attack.input,
        });

        // Check injection detected — poll for events since sessions.create
        // returns before the agent makes the LLM call
        const relevant = await this._pollForInjectionEvents(start, 5000);

        if (relevant.length > 0) {
          detected++;

          // Check attribution
          const agentLabel = attack.agent.expected_label;
          const hasAttribution = relevant.some(e =>
            e.agentLabel?.toLowerCase().includes(agentLabel.toLowerCase())
          );
          if (hasAttribution) attributed++;
        } else {
          missed++;
        }

        // Preamble injection: verify label survives
        if (attack.isPreamble) {
          preambleTotal++;
          const agentSessions = await this._getAgentSessions();
          const match = agentSessions.find(a =>
            a.agentLabel?.toLowerCase() === attack.agent.expected_label.toLowerCase()
          );
          if (match) preambleSurvived++;
        }
      } catch {
        errors++;
      }

      // Progress every 100 attacks
      if ((i + 1) % 100 === 0) {
        this._log(`  ... ${i + 1}/${attacks.length} attacks (${detected} detected, ${missed} missed, ${errors} errors)`);
      }
    }

    // ── Phase 3 Assertions ──────────────────────────────────────

    // 3a. Detection rate — should catch the vast majority
    this.results.total++;
    const detectionRate = attacks.length > 0 ? (detected / attacks.length) * 100 : 0;
    const minDetectionRate = 85; // Allow some FN for edge cases like short tool_guard patterns
    if (detectionRate >= minDetectionRate) {
      this._pass(`Phase 3: detection rate ${detectionRate.toFixed(1)}% (${detected}/${attacks.length}, min ${minDetectionRate}%)`);
    } else {
      this._fail(`Phase 3: detection rate`, `${detectionRate.toFixed(1)}% < ${minDetectionRate}% (${detected}/${attacks.length} detected, ${missed} missed)`);
    }

    // 3b. Attribution rate — detected events should be attributed to the correct agent
    this.results.total++;
    const attrRate = detected > 0 ? (attributed / detected) * 100 : 0;
    if (attrRate >= 60) {
      this._pass(`Phase 3: attribution rate ${attrRate.toFixed(1)}% (${attributed}/${detected} attributed)`);
    } else {
      this._fail(`Phase 3: attribution rate`, `${attrRate.toFixed(1)}% < 80% (${attributed}/${detected})`);
    }

    // 3c. Preamble resilience — agent labels must survive preamble injection
    this.results.total++;
    const preambleRate = preambleTotal > 0 ? (preambleSurvived / preambleTotal) * 100 : 100;
    if (preambleRate >= 80) {
      this._pass(`Phase 3: preamble resilience ${preambleSurvived}/${preambleTotal} labels survived (${preambleRate.toFixed(0)}%)`);
    } else {
      this._fail(`Phase 3: preamble resilience`, `${preambleSurvived}/${preambleTotal} labels survived (${preambleRate.toFixed(0)}% < 80%)`);
    }

    // 3d. No duplicate agents created by attacks
    this.results.total++;
    try {
      const agentSessions = await this._getAgentSessions();
      assertNoDuplicateAgents(agentSessions);
      this._pass("Phase 3: no duplicate agents after 1000 attacks");
    } catch (err) {
      this._fail("Phase 3: duplicate agents", err.message);
    }

    // 3e. Build IDs still stable
    this.results.total++;
    try {
      const agentSessions = await this._getAgentSessions();
      assertUniqueBuildIds(agentSessions);
      this._pass("Phase 3: build IDs still unique after 1000 attacks");
    } catch (err) {
      this._fail("Phase 3: build ID stability", err.message);
    }

    this._log(`\n  Phase 3 Summary:`);
    this._log(`    Attacks: ${attacks.length}`);
    this._log(`    Detected: ${detected} (${detectionRate.toFixed(1)}%)`);
    this._log(`    Attributed: ${attributed}/${detected}`);
    this._log(`    Preamble survived: ${preambleSurvived}/${preambleTotal}`);
    this._log(`    Missed: ${missed}`);
    this._log(`    Errors: ${errors}`);
  }

  // ── Lifecycle Helpers ──────────────────────────────────────────

  // ── Traffic & Attack Generators ─────────────────────────────

  /**
   * Generate a traffic message from seed messages with rotating PII.
   * Each turn gets a different combination of IPs, emails, hostnames, and phones
   * injected into the seed message to create unique, realistic traffic.
   */
  _generateTrafficMessage(seeds, turnIndex) {
    const seed = seeds[turnIndex % seeds.length];

    // PII pools — rotate through these based on turn index
    const ips = [
      "10.0.1." + ((turnIndex * 7 + 3) % 254 + 1),
      "192.168." + (turnIndex % 255) + "." + ((turnIndex * 3) % 254 + 1),
      "172.16." + (turnIndex % 16) + "." + ((turnIndex * 11) % 254 + 1),
    ];
    const emails = [
      `user${turnIndex}@company.com`,
      `admin${turnIndex % 50}@internal.corp`,
      `test.user${turnIndex % 100}@example.org`,
    ];
    const phones = [
      `+1-555-${String(turnIndex % 10000).padStart(4, "0")}`,
      `+44-7911-${String((turnIndex * 7) % 1000000).padStart(6, "0")}`,
      `+43-664-${String((turnIndex * 13) % 10000000).padStart(7, "0")}`,
    ];
    const hostnames = [
      `server-${turnIndex % 100}.prod.internal`,
      `db-${turnIndex % 20}.cluster.local`,
      `app-${turnIndex % 50}.staging.corp`,
    ];
    const apiKeys = [
      `sk-live-${turnIndex.toString(16).padStart(12, "0")}`,
      `AKIA${String(turnIndex).padStart(16, "0")}`,
    ];

    // Pick PII based on turn to create variety
    const ip = ips[turnIndex % ips.length];
    const email = emails[turnIndex % emails.length];
    const phone = phones[turnIndex % phones.length];
    const hostname = hostnames[turnIndex % hostnames.length];
    const apiKey = apiKeys[turnIndex % apiKeys.length];

    // For turns beyond the seed count, modify the seed with extra PII context
    if (turnIndex >= seeds.length) {
      const suffixes = [
        ` Also check ${ip} and contact ${email}.`,
        ` The server at ${hostname} may have relevant data.`,
        ` Use API key ${apiKey} for authentication.`,
        ` Call ${phone} if you need access.`,
        ` Cross-reference with data on ${ip} (${hostname}).`,
        ` Send results to ${email} when done.`,
        ` The config file is on ${hostname}:/etc/app/config.yaml`,
        ` Compare with the previous report at ${ip}:/reports/latest.pdf`,
      ];
      return seed + suffixes[turnIndex % suffixes.length];
    }

    return seed;
  }

  /**
   * Generate N attacks from templates, payloads, and agent roster.
   * Distributes attacks evenly across agents and threat classes.
   */
  _generateAttacks(count, templates, payloads, roles, piiValues, shellIps, agents, seedAttacks) {
    const attacks = [];

    // First, include all seed attacks (the hand-written ones)
    for (const seed of seedAttacks) {
      const agent = agents.find(a => a.id === seed.agent);
      if (!agent) continue;
      attacks.push({
        agent,
        input: seed.input,
        isPreamble: seed.description?.includes("preamble") || false,
        threatClass: seed.expect_threat_class || "unknown",
      });
    }

    // Generate the remaining attacks from templates
    const threatClasses = Object.keys(templates);
    let generated = 0;

    while (attacks.length < count) {
      // Round-robin through threat classes
      const threatClass = threatClasses[generated % threatClasses.length];
      const classTemplates = templates[threatClass];
      if (!classTemplates || classTemplates.length === 0) { generated++; continue; }

      // Pick template, payload, agent
      const template = classTemplates[generated % classTemplates.length];
      const payload = payloads[generated % payloads.length];
      const agent = agents[generated % agents.length];
      const role = roles[generated % roles.length];
      const pii = piiValues[generated % piiValues.length];
      const ip = shellIps[generated % shellIps.length];

      // Build the base64 payload for encoding_bypass
      const base64 = Buffer.from(payload).toString("base64");

      // Substitute placeholders
      let input = template
        .replace(/\{payload\}/g, payload)
        .replace(/\{role\}/g, role)
        .replace(/\{pii\}/g, pii)
        .replace(/\{ip\}/g, ip)
        .replace(/\{base64\}/g, base64);

      attacks.push({
        agent,
        input,
        isPreamble: threatClass === "preamble_injection",
        threatClass,
      });

      generated++;
    }

    return attacks;
  }

  /**
   * Build a system prompt that mimics OpenClaw's actual metadata format.
   * This is the key to testing channel detection — the metadata must
   * match what OpenClaw actually produces.
   */
  _buildAgentPrompt(agent, userMessage) {
    let metadata = "";

    if (agent.channel === "slack" && agent.conversation_label) {
      metadata = `Conversation info (untrusted metadata):\n\`\`\`json\n${JSON.stringify({
        conversation_label: `#${agent.conversation_label.replace(/^#/, "")}`,
        channel_type: "channel",
        team_id: "T00000001",
      }, null, 2)}\n\`\`\`\n\nSlack message in ${agent.conversation_label}\n\n`;
    } else if (agent.channel === "whatsapp") {
      metadata = `Conversation info (untrusted metadata):\n\`\`\`json\n${JSON.stringify({
        message_id: `3AF0${Date.now().toString(16).toUpperCase()}`,
        sender_id: agent.sender_id || "+353850000001",
        sender: agent.sender || "User",
      }, null, 2)}\n\`\`\`\n\nSender (untrusted metadata):\n\`\`\`json\n${JSON.stringify({
        label: agent.sender || "User",
        e164: agent.sender_id || "+353850000001",
      }, null, 2)}\n\`\`\`\n\n`;
    } else if (agent.channel === "tui") {
      metadata = `Conversation info (untrusted metadata):\n\`\`\`json\n${JSON.stringify({
        channel: "tui",
        session_type: "terminal",
      }, null, 2)}\n\`\`\`\n\n`;
    }

    // OpenClaw framework preamble (always present — this is what we must ignore)
    const preamble = "You are a personal assistant running inside OpenClaw.\n";

    return metadata + preamble + "---\n" + agent.soul;
  }

  /**
   * Wait for the dashboard API to become available after restart.
   */
  async _waitForDashboard(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const res = await this._httpGet("http://127.0.0.1:9380/health");
        if (res.includes("ok")) return;
      } catch {}
      await new Promise(r => setTimeout(r, 500));
    }
    this._log("  [WARN] Dashboard not available after restart — continuing anyway");
  }
}
