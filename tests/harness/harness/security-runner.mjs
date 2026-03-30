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

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";

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

      // Check security events
      const secEvents = await this._getSecurityEvents();
      const assertions = scenario.assertions || {};

      // Injection detection check
      if (assertions.injection_detected === true) {
        const relevant = secEvents.filter(e =>
          e.eventType === "injection_detected" &&
          e.timestamp > start
        );
        if (relevant.length === 0) {
          throw new Error(`Expected injection detected but none found`);
        }
        if (assertions.injection_threat_class) {
          const hasClass = relevant.some(e => e.threatClass === assertions.injection_threat_class);
          if (!hasClass) {
            throw new Error(`Expected threat class "${assertions.injection_threat_class}" but got: ${relevant.map(e => e.threatClass).join(", ")}`);
          }
        }
        if (assertions.injection_severity) {
          const hasSev = relevant.some(e => e.severity === assertions.injection_severity);
          if (!hasSev) {
            throw new Error(`Expected severity "${assertions.injection_severity}" but got: ${relevant.map(e => e.severity).join(", ")}`);
          }
        }
      } else if (assertions.injection_detected === false) {
        const relevant = secEvents.filter(e =>
          e.eventType === "injection_detected" &&
          e.timestamp > start
        );
        if (relevant.length > 0) {
          throw new Error(`Expected NO injection but found ${relevant.length}: ${relevant.map(e => e.signatureId).join(", ")}`);
        }
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
        const lastReq = llmRequests[llmRequests.length - 1] || "";
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
    const start = Date.now();
    try {
      const agent = agentMap.get(scenario.agent);
      if (!agent) throw new Error(`Unknown agent: ${scenario.agent}`);

      const sessionKey = `sec-mt-${scenario.agent}-${Date.now()}`;

      for (let i = 0; i < scenario.turns.length; i++) {
        const turn = scenario.turns[i];
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
          const secEvents = await this._getSecurityEvents();
          const relevant = secEvents.filter(e =>
            e.eventType === "injection_detected" &&
            e.timestamp > turnStart
          );
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
          const lastReq = llmRequests[llmRequests.length - 1] || "";
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
        const secEvents = await this._getSecurityEvents();
        const relevant = secEvents.filter(e =>
          e.eventType === "injection_detected" && e.timestamp > start
        );
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
          const allText = recentRequests.join("\n");
          for (const val of sub.assertions.llm_must_not_see) {
            if (allText.includes(val)) {
              throw new Error(`Parallel[${sub.agent}]: LLM saw real value: "${val}"`);
            }
          }
        }
      }

      // Check injection detection for parallel scenarios
      const secEvents = await this._getSecurityEvents();
      for (const sub of scenario.parallel) {
        if (sub.assertions?.injection_detected) {
          const relevant = secEvents.filter(e =>
            e.eventType === "injection_detected" && e.timestamp > start
          );
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
    // Primary: use dashboard API (works in all OpenClaw versions)
    try {
      const res = await this._httpGet("http://127.0.0.1:9380/api/events");
      const parsed = JSON.parse(res);
      return parsed.events || [];
    } catch {}
    // Fallback: try tools.call (older approach)
    try {
      const result = this._gatewayToolCall("shroud_security", {});
      const parsed = JSON.parse(result);
      return parsed.recentEvents || [];
    } catch {
      return [];
    }
  }

  async _getAgentSessions() {
    // Primary: use dashboard API
    try {
      const res = await this._httpGet("http://127.0.0.1:9380/api/agents");
      const parsed = JSON.parse(res);
      return parsed.agents || [];
    } catch {}
    // Fallback: try tools.call
    try {
      const result = this._gatewayToolCall("shroud_security", {});
      const parsed = JSON.parse(result);
      return parsed.agentSessions || [];
    } catch {
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

  _gatewayToolCall(toolName, input) {
    const bin = this._getOpenClawBin();
    const args = [
      bin, "gateway", "call", "tools.call",
      "--expect-final",
      "--timeout", "10000",
      "--json",
      "--url", `ws://127.0.0.1:${this.gatewayPort}`,
      "--token", "shroud-test-token",
      "--params", JSON.stringify({ name: toolName, input }),
    ];
    try {
      const result = execFileSync("node", args, {
        timeout: 15000,
        encoding: "utf-8",
        env: { ...process.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
      });
      // Parse tool response — extract text content
      const parsed = JSON.parse(result);
      if (parsed?.content?.[0]?.text) return parsed.content[0].text;
      return result;
    } catch {
      return "{}";
    }
  }

  _httpGet(url) {
    return new Promise((resolve, reject) => {
      http.get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => resolve(data));
        res.on("error", reject);
      }).on("error", reject);
    });
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
}
