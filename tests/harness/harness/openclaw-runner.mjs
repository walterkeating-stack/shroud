#!/usr/bin/env node
/**
 * OpenClaw Integration Runner — E2E tests inside a Docker container.
 *
 * Runs inside Docker (set up by compat/entrypoint.sh):
 *   1. OpenClaw is pre-installed globally, Shroud from tarball
 *   2. Starts ONE gateway process for all tests
 *   3. Sends messages via `openclaw gateway call sessions.create/send`
 *   4. Channel E2E: Slack webhook injection, WhatsApp Baileys mock,
 *      cron schedule, TUI via sessions.create
 *   5. Mock servers (LLM, Slack, WhatsApp) run on localhost
 *   6. /etc/hosts redirects API hostnames to localhost
 *   7. Echo mode LLM for deobfuscation round-trip verification
 */

import { spawn, execFileSync } from "node:child_process";
import {
  mkdirSync, writeFileSync, existsSync, readFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import crypto from "node:crypto";
import http from "node:http";
import {
  assertNoCgnatLeak,
  assertNoCgnatRangeLeak,
  assertNoUlaLeak,
} from "../lib/assertions.mjs";
import { Reporter } from "./reporter.mjs";

export class OpenClawRunner {
  constructor(opts = {}) {
    this.shroudPath = opts.shroudPath || resolve(import.meta.dirname, "../../..");
    this.openclawVersion = opts.openclawVersion || "latest";
    this.verbose = opts.verbose || false;
    this.scenario = opts.scenario || null;

    this.stateDir = process.env.OPENCLAW_STATE_DIR || "/shroud/state";
    this.mockLlmPort = null;
    this.mockLlmProc = null;
    this.mockSlackPort = null;
    this.mockSlackProc = null;
    this.mockSlack443Proc = null;
    this.mockWhatsAppPort = null;
    this.mockWhatsAppProc = null;
    this.gatewayProc = null;
    this.gatewayPort = null;
    this.gatewayStderr = "";
    this.gatewayStdout = "";
    this.results = { scenarios: [], passed: 0, failed: 0, skipped: 0, duration: 0 };
  }

  async run() {
    const startTime = Date.now();
    this._log("OpenClaw Integration Smoke Test");
    this._log("=".repeat(50));

    try {
      await this._runDocker();
    } finally {
      await this._teardown();
    }

    this.results.duration = Date.now() - startTime;

    Reporter.console(this.results, this.verbose);
    return this.results;
  }

  // ── Docker mode: single gateway, batched tests ─────────────

  async _runDocker() {
    for (const sub of ["extensions", "workspace", "logs", "credentials", "agents"]) {
      mkdirSync(join(this.stateDir, sub), { recursive: true });
    }

    this._log("Single gateway, batched tests");

    // 1. Start mock servers
    await this._startMockLlm();
    await this._startMockSlack();
    await this._startMockWhatsApp();

    // Also start mock Slack on port 443 for the Slack SDK's HTTPS fallback path.
    // /etc/hosts redirects slack.com → 127.0.0.1. Some SDK paths connect via
    // https://slack.com:443 which bypasses our WebClient URL patch.
    await this._startMockSlackOnPort(443);

    // 2. Write config with mock LLM/Slack/WhatsApp ports + channel config
    this._writeConfig();

    // 3. Start ONE gateway (all tests go through this)
    await this._startGateway();

    // 4. Run all scenarios via gateway RPC
    await this._runScenariosViaGateway();
  }

  async _startGateway() {
    const bin = this._getOpenClawBin();
    this.gatewayPort = 19000 + Math.floor(Math.random() * 500);
    const slackInterceptPath = resolve(import.meta.dirname, "..", "mock-slack", "intercept.cjs");
    const waInterceptPath = resolve(import.meta.dirname, "..", "mock-whatsapp", "intercept.cjs");

    const env = {
      ...this._agentEnv(),
      MOCK_SLACK_PORT: String(this.mockSlackPort),
      MOCK_SLACK_URL: `http://127.0.0.1:${this.mockSlackPort}/api/`,
      MOCK_WHATSAPP_PORT: String(this.mockWhatsAppPort || ""),
      MOCK_WHATSAPP_INJECT_PORT: "9301",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      NODE_OPTIONS: `--require ${slackInterceptPath} --require ${waInterceptPath}`,
      OPENCLAW_GATEWAY_PORT: String(this.gatewayPort),
    };
    // Gateway needs channels enabled
    delete env.OPENCLAW_SKIP_CHANNELS;
    delete env.OPENCLAW_SKIP_CRON;

    // --dev: auto-creates dev config + workspace without BOOTSTRAP.md
    this.gatewayProc = spawn("node", [bin, "gateway", "run", "--dev", "--auth", "token", "--token", "shroud-test-token", "--port", String(this.gatewayPort)], {
      stdio: ["pipe", "pipe", "pipe"],
      env,
      cwd: join(this.stateDir, "workspace"),
    });

    this.gatewayProc.stderr.on("data", (d) => { this.gatewayStderr += d; });
    this.gatewayProc.stdout.on("data", (d) => { this.gatewayStdout += d; });

    // Wait for gateway to be listening
    try {
      await this._waitFor(
        () => {
          const all = this.gatewayStdout + this.gatewayStderr;
          return all.includes("listening") || all.includes("Plugin loaded");
        },
        30000, "gateway to start", this.gatewayProc,
      );
    } catch (err) {
      this._log(`Gateway failed to start. stderr:\n${this.gatewayStderr.slice(-1000)}`);
      this._log(`Gateway stdout:\n${this.gatewayStdout.slice(-500)}`);
      throw err;
    }
    // Extra settle time for HTTP server to bind
    await new Promise(r => setTimeout(r, 2000));

    this._log(`Gateway started on port ${this.gatewayPort}`);

    // Verify plugin loaded
    if (!this.gatewayStdout.includes("Plugin loaded") && !this.gatewayStderr.includes("Plugin loaded")) {
      throw new Error("Shroud plugin did not load in gateway — check config");
    }
    this._log("Shroud plugin loaded in gateway");

    // Wait for Slack channel to start
    try {
      await this._waitFor(
        () => {
          const all = this.gatewayStdout + this.gatewayStderr;
          return all.includes("http mode listening") || all.includes("slack_bolt_authorization_error") || all.includes("invalid_auth");
        },
        30000, "Slack channel to start", this.gatewayProc,
      );
      const all = this.gatewayStdout + this.gatewayStderr;
      if (all.includes("http mode listening")) {
        this._log("Slack channel started in HTTP mode");
      }
    } catch {
      this._log("Slack channel did not start (non-fatal)");
    }
  }

  async _runScenariosViaGateway() {
    const scenarios = this._buildScenarios();
    const tests = [];
    let testIdx = 0;

    this._log(`\nRunning ${scenarios.length} scenarios via gateway...`);
    this._log("-".repeat(50));

    for (const s of scenarios) {
      this.results.total++;
      testIdx++;
      // Small delay between gateway calls to avoid socket churn
      if (testIdx > 1) await new Promise(r => setTimeout(r, 500));
      const result = await this._runOneViaGateway(s, testIdx);
      tests.push(result);

      if (result.status === "pass") {
        this.results.passed++;
        this._log(`  \x1b[32m\u2714\x1b[0m ${s.name}  \x1b[2m(${result.duration}ms)\x1b[0m`);
      } else if (result.status === "skip") {
        this.results.skipped++;
        this._log(`  \x1b[33m\u2298\x1b[0m ${s.name}  \x1b[2m(${result.error})\x1b[0m`);
      } else {
        this.results.failed++;
        this._log(`  \x1b[31m\u2718\x1b[0m ${s.name}`);
        this._log(`    \x1b[31m${result.error}\x1b[0m`);
      }
    }

    this.results.scenarios = [{
      name: "OpenClaw Integration",
      file: "openclaw-runner",
      passed: this.results.passed,
      failures: this.results.failed,
      duration: tests.reduce((a, t) => a + t.duration, 0),
      tests,
    }];
  }

  async _runOneViaGateway(scenario, idx) {
    const start = Date.now();
    const result = { name: scenario.name, status: "pass", duration: 0, error: null };

    try {
      // Slack E2E: inject webhook, check mock Slack response
      if (scenario.slackE2E) {
        await this._runSlackE2EViaGateway(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // WhatsApp E2E: inject message via mock, check response
      if (scenario.whatsAppE2E) {
        await this._runWhatsAppE2E(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // Cron E2E: verify cron schedule fires
      if (scenario.cronE2E) {
        await this._runCronE2E(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // Multi-turn: send multiple messages to same session
      if (scenario.multiTurn) {
        await this._runMultiTurnViaGateway(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // Standard scenario: send via sessions.send, check LLM
      await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

      const sessionKey = `test-${idx}-${Date.now()}`;
      // Create session + send initial message, wait for agent to finish
      const agentResponse = this._gatewayCall("sessions.create", {
        key: sessionKey,
        message: scenario.message,
      }, { timeout: 45000 });

      // Wait for LLM to receive the request (gateway call may return before LLM log updates)
      let llmRequests = [];
      for (let attempt = 0; attempt < 10; attempt++) {
        await new Promise(r => setTimeout(r, 300));
        llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
        if (Array.isArray(llmRequests) && llmRequests.length > 0) break;
      }
      if (!Array.isArray(llmRequests) || llmRequests.length === 0) {
        throw new Error("Mock LLM received 0 requests — agent did not reach the model");
      }

      // LLM must NOT have seen real PII
      if (scenario.realValues?.length > 0) {
        const allContent = JSON.stringify(llmRequests);
        for (const val of scenario.realValues) {
          if (allContent.includes(val)) {
            throw new Error(`LLM saw real PII value: "${val}" — fetch intercept failed`);
          }
        }
      }

      // LLM MUST see these values (passthrough assertions)
      if (scenario.checkLlmSees?.length > 0) {
        const allContent = JSON.stringify(llmRequests);
        for (const val of scenario.checkLlmSees) {
          if (!allContent.includes(val)) {
            throw new Error(
              `LLM should see "${val}" but it was obfuscated — ` +
              `public URLs and workspace paths must pass through`
            );
          }
        }
      }

      // No CGNAT/ULA leaks in agent response
      const responseText = typeof agentResponse === "string"
        ? agentResponse
        : JSON.stringify(agentResponse || "");
      if (responseText) {
        assertNoCgnatLeak(responseText);
        assertNoCgnatRangeLeak(responseText);
        assertNoUlaLeak(responseText);
      }

      // Deobfuscation check: with echo mode, the LLM echoes obfuscated text.
      // After deobfuscation, the channel output should contain real values.
      if (scenario.realValues?.length > 0 && scenario.checkDeobfuscation) {
        for (const val of scenario.realValues) {
          if (!responseText.includes(val)) {
            throw new Error(
              `Deobfuscation failed: response should contain real value "${val}" ` +
              `but it wasn't restored. Response: ${responseText.slice(0, 200)}`
            );
          }
        }
      }

      // Audit log check
      if (scenario.checkAudit) {
        const auditLine = this.gatewayStderr.split("\n").find(l => l.includes('"event":"shroud.audit.obfuscate"'));
        if (auditLine) {
          const jsonStart = auditLine.indexOf("{");
          const jsonEnd = auditLine.lastIndexOf("}");
          if (jsonStart >= 0 && jsonEnd > jsonStart) {
            const audit = JSON.parse(auditLine.slice(jsonStart, jsonEnd + 1));
            if (!audit.req) throw new Error("Audit log missing request ID");
            if (!audit.proofIn) throw new Error("Audit log missing proofIn hash");
            if (!audit.proofOut) throw new Error("Audit log missing proofOut hash");
          }
        }
      }

      // Stats file check
      if (scenario.checkStats) {
        const statsPath = join(this.stateDir, "shroud-stats.json");
        const defaultStats = "/tmp/shroud-stats.json";
        const found = existsSync(statsPath) ? statsPath : existsSync(defaultStats) ? defaultStats : null;
        if (found) {
          const stats = JSON.parse(readFileSync(found, "utf-8"));
          if (stats.storeMappings === undefined) throw new Error("Stats file missing storeMappings");
          if (!stats.updatedAt) throw new Error("Stats file missing updatedAt timestamp");
        } else {
          throw new Error("Stats file not written");
        }
      }
    } catch (err) {
      result.status = "fail";
      result.error = err.message;
    }

    result.duration = Date.now() - start;
    return result;
  }

  _gatewayCall(method, params, opts = {}) {
    const bin = this._getOpenClawBin();
    const paramsJson = JSON.stringify(params);
    const expectFinal = opts.expectFinal !== false; // default true
    const args = [
      bin, "gateway", "call", method,
      ...(expectFinal ? ["--expect-final"] : []),
      "--timeout", String(opts.timeout || 30000),
      "--json",
      "--url", `ws://127.0.0.1:${this.gatewayPort}`,
      "--token", "shroud-test-token",
      "--params", paramsJson,
    ];
    try {
      const output = execFileSync("node", args, {
        encoding: "utf-8",
        timeout: 60000,
        env: this._agentEnv(),
        cwd: join(this.stateDir, "workspace"),
      });
      try { return JSON.parse(output); } catch { return output.trim(); }
    } catch (err) {
      // execFileSync throws on non-zero exit — extract useful info
      const stderr = err.stderr || "";
      const stdout = err.stdout || "";
      if (this.verbose) {
        this._log(`[gateway-call] stderr: ${stderr.slice(-300)}`);
        this._log(`[gateway-call] stdout: ${stdout.slice(-300)}`);
      }
      throw new Error(`Gateway call ${method} failed: ${stderr.slice(0, 200) || err.message}`);
    }
  }

  // ── Slack E2E via gateway webhook ──────────────────────────

  async _runSlackE2EViaGateway(scenario) {
    // Clear mock state
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockSlackPort}/messages`);

    // Read Slack signing secret from config
    const config = JSON.parse(readFileSync(join(this.stateDir, "openclaw.json"), "utf-8"));
    const slackSigningSecret = config.channels?.slack?.signingSecret;
    if (!slackSigningSecret) throw new Error("Slack signing secret not found in config");

    this._log(`[slack-e2e] Signing secret: ${slackSigningSecret}, gateway port: ${this.gatewayPort}`);

    // Inject a Slack message event to the gateway webhook
    const timestamp = Math.floor(Date.now() / 1000);
    const channel = scenario.slackChannel || "C00000001";
    const user = scenario.slackUser || "U00000001";
    const eventId = `Ev${Date.now()}${Math.random().toString(36).slice(2, 6)}`;
    const eventBody = JSON.stringify({
      type: "event_callback",
      token: "mock-verification-token",
      team_id: "T00000001",
      api_app_id: "A00000001",
      event_id: eventId,
      event_time: timestamp,
      event: {
        type: "message",
        subtype: undefined,
        channel,
        user,
        text: scenario.message,
        ts: `${timestamp}.000001`,
        channel_type: "channel",
      },
    });
    const sigBasestring = `v0:${timestamp}:${eventBody}`;
    const signature = "v0=" + crypto.createHmac("sha256", slackSigningSecret)
      .update(sigBasestring).digest("hex");

    const webhookResp = await this._httpReq(
      "POST", `http://127.0.0.1:${this.gatewayPort}/slack/events`,
      null,
      { "X-Slack-Request-Timestamp": String(timestamp), "X-Slack-Signature": signature },
      eventBody,
    );
    this._log(`[slack-e2e] Webhook sent, waiting for delivery...`);

    // Wait for mock Slack to receive outbound message
    const allGatewayOutput = () => this.gatewayStdout + this.gatewayStderr;

    await this._waitFor(
      async () => {
        // Check if gateway reported Slack auth failure
        const output = allGatewayOutput();
        if (output.includes("invalid_auth") ||
            output.includes("not_authed") ||
            output.includes("Slack adapter failed") ||
            output.includes("slack_bolt_authorization_error")) {
          throw new Error("Slack extension rejected mock credentials");
        }
        const msgs = await this._httpReq("GET", `http://127.0.0.1:${this.mockSlackPort}/messages`);
        return Array.isArray(msgs) && msgs.length > 0;
      },
      45000, "Slack mock to receive outbound message", this.gatewayProc,
    );

    // Allow duplicate deliveries to arrive
    await new Promise(r => setTimeout(r, 1000));

    const slackMessages = await this._httpReq("GET", `http://127.0.0.1:${this.mockSlackPort}/messages`);

    // No duplicate messages
    const distinct = slackMessages.filter(m => !m.updated);
    if (distinct.length > 1) {
      throw new Error(
        `Slack received ${distinct.length} messages — expected 1. ` +
        `Duplicate delivery. Texts: ${JSON.stringify(distinct.map(m => m.text?.slice(0, 60)))}`,
      );
    }
    if (distinct.length === 0) {
      throw new Error("Slack received 0 messages — delivery failed");
    }

    // No fake tokens in delivered message
    const allText = slackMessages.map(m => m.text || "").join(" ");
    const cgnatPattern = /\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/;
    if (cgnatPattern.test(allText)) {
      throw new Error(`Slack message contains CGNAT fake: ${allText.slice(0, 200)}`);
    }

    // Deobfuscation: with echo mode, Slack-delivered message should contain real values
    if (scenario.realValues?.length > 0) {
      for (const val of scenario.realValues) {
        if (!allText.includes(val)) {
          throw new Error(
            `Slack deobfuscation failed: delivered message should contain "${val}" ` +
            `but it wasn't restored. Message: ${allText.slice(0, 300)}`
          );
        }
      }
    }

    // LLM must not have seen real PII
    const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    if (llmRequests.length > 0 && scenario.realValues?.length > 0) {
      const allLlm = JSON.stringify(llmRequests);
      for (const val of scenario.realValues) {
        if (allLlm.includes(val)) {
          throw new Error(`LLM saw real PII in Slack E2E path: "${val}"`);
        }
      }
    }

    // Public URL passthrough
    if (scenario.checkUrlPassthrough && llmRequests.length > 0) {
      const allLlm = JSON.stringify(llmRequests);
      if (!allLlm.includes(scenario.checkUrlPassthrough)) {
        throw new Error(`Public URL "${scenario.checkUrlPassthrough}" was obfuscated`);
      }
    }

    // Workspace path passthrough
    if (scenario.checkPathPassthrough && llmRequests.length > 0) {
      const allLlm = JSON.stringify(llmRequests);
      for (const path of scenario.checkPathPassthrough) {
        if (!allLlm.includes(path)) {
          throw new Error(`Workspace path "${path}" was obfuscated`);
        }
      }
    }
  }

  // ── WhatsApp E2E ────────────────────────────────────────────

  async _runWhatsAppE2E(scenario) {
    // Clear mock state
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockWhatsAppPort}/messages`);

    // Inject an inbound WhatsApp message via the in-process injection server
    // (runs inside the gateway process, registered by the Baileys intercept)
    const from = scenario.whatsAppFrom || "+353850000001";
    const jid = from.replace("+", "") + "@s.whatsapp.net";
    const injectPort = 9301; // MOCK_WHATSAPP_INJECT_PORT
    await this._httpReq("POST", `http://127.0.0.1:${injectPort}/inject`, {
      from: jid,
      text: scenario.message,
      pushName: "Test User",
    });

    // Wait for mock WhatsApp to receive outbound message (agent response)
    await this._waitFor(
      async () => {
        const msgs = await this._httpReq("GET", `http://127.0.0.1:${this.mockWhatsAppPort}/messages`);
        return Array.isArray(msgs) && msgs.length > 0;
      },
      30000, "WhatsApp mock to receive outbound message", this.gatewayProc,
    );

    // Allow delivery to complete
    await new Promise(r => setTimeout(r, 500));

    const waMessages = await this._httpReq("GET", `http://127.0.0.1:${this.mockWhatsAppPort}/messages`);
    if (!Array.isArray(waMessages) || waMessages.length === 0) {
      throw new Error("WhatsApp mock received 0 messages — delivery failed");
    }

    // No CGNAT fakes in delivered message
    const allText = waMessages.map(m => m.text || "").join(" ");
    const cgnatPattern = /\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/;
    if (cgnatPattern.test(allText)) {
      throw new Error(`WhatsApp message contains CGNAT fake: ${allText.slice(0, 200)}`);
    }

    // Deobfuscation: echo mode means delivered message should contain real values
    if (scenario.realValues?.length > 0) {
      for (const val of scenario.realValues) {
        if (!allText.includes(val)) {
          throw new Error(
            `WhatsApp deobfuscation failed: delivered message should contain "${val}" ` +
            `but it wasn't restored. Message: ${allText.slice(0, 300)}`
          );
        }
      }
    }

    // LLM must not have seen real PII
    const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    if (llmRequests.length > 0 && scenario.realValues?.length > 0) {
      const allLlm = JSON.stringify(llmRequests);
      for (const val of scenario.realValues) {
        if (allLlm.includes(val)) {
          throw new Error(`LLM saw real PII in WhatsApp E2E path: "${val}"`);
        }
      }
    }
  }

  // ── Multi-turn via gateway ─────────────────────────────────

  async _runMultiTurnViaGateway(scenario) {
    const sessionKey = `multi-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    for (let i = 0; i < scenario.turns.length; i++) {
      const turn = scenario.turns[i];
      await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

      const method = i === 0 ? "sessions.create" : "sessions.send";
      this._gatewayCall(method, { key: sessionKey, message: turn.message }, { timeout: 45000 });

      // Wait for LLM to log the request
      let llmRequests = [];
      for (let attempt = 0; attempt < 10; attempt++) {
        await new Promise(r => setTimeout(r, 300));
        llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
        if (Array.isArray(llmRequests) && llmRequests.length > 0) break;
      }
      if (!Array.isArray(llmRequests) || llmRequests.length === 0) {
        throw new Error(`Turn ${i + 1}: Mock LLM received 0 requests`);
      }

      const allContent = JSON.stringify(llmRequests);
      for (const val of turn.realValues) {
        if (allContent.includes(val)) {
          throw new Error(
            `Turn ${i + 1}: LLM saw real PII "${val}" — ` +
            (i > 0
              ? "deobfuscated assistant message from previous turn leaked to LLM context"
              : "fetch intercept failed"),
          );
        }
      }
    }
  }

  // ── Cron E2E ───────────────────────────────────────────────

  async _runCronE2E(scenario) {
    // Cron test: add a cron job via gateway, wait for it to fire, verify PII obfuscation
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

    // Add a cron job that fires every minute via CLI
    const cronMessage = scenario.cronMessage || "Cron health check: server db.prod.internal at 172.16.0.50 needs monitoring";
    try {
      execFileSync("node", [
        this._getOpenClawBin(), "cron", "add",
        "--name", "shroud-test-cron",
        "--cron", "* * * * *",
        "--message", cronMessage,
        "--url", `ws://127.0.0.1:${this.gatewayPort}`,
        "--token", "shroud-test-token",
        "--exact",
      ], {
        encoding: "utf-8",
        timeout: 15000,
        env: this._agentEnv(),
        cwd: join(this.stateDir, "workspace"),
      });
    } catch (cliErr) {
      throw new Error(`Failed to add cron job: ${cliErr.stderr || cliErr.message}`);
    }

    // Wait for cron to fire (up to 90s for a 1-minute schedule)
    await this._waitFor(
      async () => {
        const reqs = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
        return Array.isArray(reqs) && reqs.length > 0;
      },
      scenario.cronTimeoutMs || 90000, "cron job to fire", this.gatewayProc,
    );

    const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    if (!Array.isArray(llmRequests) || llmRequests.length === 0) {
      throw new Error("Cron job did not fire — mock LLM received 0 requests");
    }

    // If the cron message contains PII, verify it was obfuscated
    if (scenario.realValues?.length > 0) {
      const allContent = JSON.stringify(llmRequests);
      for (const val of scenario.realValues) {
        if (allContent.includes(val)) {
          throw new Error(`Cron: LLM saw real PII "${val}" — obfuscation failed in cron path`);
        }
      }
    }
  }

  // ── Config ────────────────────────────────────────────────

  _writeConfig() {
    const statsFile = join(this.stateDir, "shroud-stats.json");
    const configPath = join(this.stateDir, "openclaw.json");

    // Merge with existing config (plugin was installed via CLI in entrypoint)
    let existing = {};
    if (existsSync(configPath)) {
      try { existing = JSON.parse(readFileSync(configPath, "utf-8")); } catch {}
    }

    const config = {
      ...existing,
      meta: { lastTouchedVersion: this.openclawVersion, lastTouchedAt: new Date().toISOString() },
      gateway: {
        mode: "local",
        auth: { mode: "token", token: "shroud-test-token" },
      },
      agents: {
        defaults: {
          workspace: join(this.stateDir, "workspace"),
          model: { primary: "mock-provider/mock-model" },
          timeoutSeconds: 30,
        },
      },
      // Sandbox exec: run agent tool calls inside containers
      ...(process.env.SHROUD_TEST_SANDBOX === "1" ? {
        tools: {
          exec: {
            host: "sandbox",
            security: "full",
            ask: "off",
          },
        },
      } : {}),
      models: {
        mode: "merge",
        providers: {
          "mock-provider": {
            baseUrl: `http://127.0.0.1:${this.mockLlmPort}/v1`,
            apiKey: "sk-sandbox-dummy",
            auth: "api-key",
            api: "openai-completions",
            models: [{
              id: "mock-model",
              name: "Sandbox Mock",
              reasoning: false,
              input: ["text"],
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
              contextWindow: 128000,
              maxTokens: 4096,
            }],
          },
        },
      },
      plugins: {
        ...(existing.plugins || {}),
        entries: {
          ...(existing.plugins?.entries || {}),
          "shroud-privacy": {
            ...(existing.plugins?.entries?.["shroud-privacy"] || {}),
            enabled: true,
            config: {
              auditEnabled: true,
              auditLogFormat: "json",
              auditIncludeProofHashes: true,
              auditHashSalt: "test-salt",
            },
          },
        },
      },
    };

    // Add channel config for E2E tests
    if (this.mockSlackPort) {
      const slackSigningSecret = crypto.randomBytes(16).toString("hex");
      config.channels = {
        ...(config.channels || {}),
        slack: {
          mode: "http",
          enabled: true,
          streaming: "off",
          nativeStreaming: false,
          botToken: "SHROUD_TEST_SLACK_TOKEN",
          signingSecret: slackSigningSecret,
          webhookPath: "/slack/events",
          groupPolicy: "allowlist",
          channels: {
            "C00000001": { requireMention: false },
            "C00000002": { requireMention: false },
          },
          dmPolicy: "allowlist",
          allowFrom: ["U00000001", "U00000002"],
        },
      };
      // WhatsApp channel (uses Baileys intercept)
      if (this.mockWhatsAppPort) {
        config.channels.whatsapp = {
          ...(config.channels?.whatsapp || {}),
          enabled: true,
          dmPolicy: "allowlist",
          allowFrom: ["+353850000001"],
          accounts: {
            ...(config.channels?.whatsapp?.accounts || {}),
            default: {
              ...(config.channels?.whatsapp?.accounts?.default || {}),
              enabled: true,
              dmPolicy: "allowlist",
              allowFrom: ["+353850000001"],
            },
          },
        };
      }
    }

    writeFileSync(configPath, JSON.stringify(config, null, 2));
    this._log(`Config written (LLM: 127.0.0.1:${this.mockLlmPort})`);
  }

  // ── Mock LLM ──────────────────────────────────────────────

  async _startMockLlm() {
    const serverPath = resolve(import.meta.dirname, "..", "mock-llm", "server.mjs");

    return new Promise((res, reject) => {
      this.mockLlmProc = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PORT: "0", MOCK_LLM_NO_TOOLS: "1", MOCK_LLM_ECHO: "1" },
      });

      const timeout = setTimeout(() => reject(new Error("Mock LLM timeout")), 10000);
      const rl = createInterface({ input: this.mockLlmProc.stdout });

      rl.once("line", (line) => {
        try {
          const info = JSON.parse(line);
          if (info.port) { clearTimeout(timeout); this.mockLlmPort = info.port; res(); }
        } catch (e) { clearTimeout(timeout); reject(e); }
      });

      this.mockLlmProc.on("error", (e) => { clearTimeout(timeout); reject(e); });
    });
  }

  // ── Mock Slack ──────────────────────────────────────────────

  async _startMockSlack() {
    const serverPath = resolve(import.meta.dirname, "..", "mock-slack", "server.mjs");
    return new Promise((res, reject) => {
      this.mockSlackProc = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PORT: "0" },
      });
      const timeout = setTimeout(() => reject(new Error("Mock Slack timeout")), 10000);
      const rl = createInterface({ input: this.mockSlackProc.stdout });
      rl.once("line", (line) => {
        try {
          const info = JSON.parse(line);
          if (info.port) { clearTimeout(timeout); this.mockSlackPort = info.port; res(); }
        } catch (e) { clearTimeout(timeout); reject(e); }
      });
      this.mockSlackProc.on("error", (e) => { clearTimeout(timeout); reject(e); });
    });
  }

  async _startMockSlackOnPort(port) {
    // Start HTTPS proxy on port 443 that forwards to the HTTP mock Slack server.
    // /etc/hosts redirects slack.com → 127.0.0.1, Slack SDK connects via HTTPS to 443.
    // The proxy serves TLS with a self-signed cert and forwards to mock Slack HTTP.
    const proxyPath = resolve(import.meta.dirname, "..", "mock-slack", "https-proxy.mjs");
    return new Promise((res) => {
      this.mockSlack443Proc = spawn("node", [proxyPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          HTTPS_PORT: String(port),
          MOCK_SLACK_PORT: String(this.mockSlackPort),
        },
      });
      const timeout = setTimeout(() => {
        this._log(`HTTPS proxy on port ${port}: failed to start (non-fatal)`);
        res();
      }, 10000);
      const rl = createInterface({ input: this.mockSlack443Proc.stdout });
      rl.once("line", (line) => {
        clearTimeout(timeout);
        this._log(`HTTPS proxy for Slack SDK listening on port ${port}`);
        res();
      });
      this.mockSlack443Proc.on("error", () => { clearTimeout(timeout); res(); });
    });
  }

  async _startMockWhatsApp() {
    const serverPath = resolve(import.meta.dirname, "..", "mock-whatsapp", "server.mjs");
    return new Promise((res, reject) => {
      this.mockWhatsAppProc = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PORT: "0" },
      });
      const timeout = setTimeout(() => reject(new Error("Mock WhatsApp timeout")), 10000);
      const rl = createInterface({ input: this.mockWhatsAppProc.stdout });
      rl.once("line", (line) => {
        try {
          const info = JSON.parse(line);
          if (info.port) { clearTimeout(timeout); this.mockWhatsAppPort = info.port; res(); }
        } catch (e) { clearTimeout(timeout); reject(e); }
      });
      this.mockWhatsAppProc.on("error", (e) => { clearTimeout(timeout); reject(e); });
    });
  }

  // ── Scenarios ─────────────────────────────────────────────

  _buildScenarios() {
    const all = [
      // 10 PII smoke tests covering the core entity types
      {
        name: "Email through OpenClaw plugin",
        message: "Contact admin@internal-corp.net about the outage",
        realValues: ["admin@internal-corp.net"],
      },
      {
        name: "IPv4 through OpenClaw plugin",
        message: "The switch at 10.200.1.5 is flapping on Gi0/1",
        realValues: ["10.200.1.5"],
      },
      {
        name: "Phone number through OpenClaw plugin",
        message: "Call the NOC at +14155551234 for on-call support",
        realValues: ["+14155551234"],
      },
      {
        name: "Hostname through OpenClaw plugin",
        message: "hostname SYD-ACC-SW-12\ninterface Gi0/1\n ip address 10.200.1.5 255.255.255.0",
        realValues: ["SYD-ACC-SW-12", "10.200.1.5"],
      },
      {
        name: "Credential through OpenClaw plugin",
        message: "enable secret 5 $1$mERo$ILwq/1h1\nsnmp-server host 10.1.0.1 version 2c TrapComm",
        realValues: ["$1$mERo$ILwq/1h1", "10.1.0.1"],
      },
      {
        name: "Multi-entity through OpenClaw plugin",
        message: "ALERT: 10.50.1.1 down. Contact admin@noc.internal or call +14155559876. Host: DAL-CORE-RTR-01",
        realValues: ["10.50.1.1", "admin@noc.internal", "+14155559876", "DAL-CORE-RTR-01"],
      },
      {
        name: "BGP config through OpenClaw plugin",
        message: "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 password 7 070C285F4D06",
        realValues: ["10.0.0.2", "070C285F4D06"],
      },
      {
        name: "Connection string through OpenClaw plugin",
        message: "The database URL is postgresql://admin:SuperSecret123@db.internal-corp.net:5432/prod",
        realValues: ["SuperSecret123"],
      },
      {
        name: "IBAN through OpenClaw plugin",
        message: "Wire payment to AT611904300234573201 for invoice #4412",
        realValues: ["AT611904300234573201"],
      },
      {
        name: "API key through OpenClaw plugin",
        message: "Use the key SHROUD_TEST_OPENAI_KEY for the staging API",
        realValues: ["SHROUD_TEST_OPENAI_KEY"],
      },
      // ── False positive regression: production bugs that must never recur ──
      {
        name: "Public URL not obfuscated (GitHub)",
        message: "Check https://github.com/wkeything/shroud for me",
        realValues: [],
        checkLlmSees: ["github.com"],
      },
      {
        name: "Public URL not obfuscated (npm)",
        message: "Look at https://www.npmjs.com/package/shroud-privacy",
        realValues: [],
        checkLlmSees: ["npmjs.com"],
      },
      {
        name: "Workspace path not obfuscated (/home)",
        message: "Run python3 /home/user/.openclaw/workspace/scripts/test.py",
        realValues: [],
        checkLlmSees: ["/home/user/.openclaw/workspace/scripts/test.py"],
      },
      {
        name: "Workspace path not obfuscated (/tmp)",
        message: "Save results to /tmp/shroud-test-output.json",
        realValues: [],
        checkLlmSees: ["/tmp/shroud-test-output.json"],
      },
      {
        name: "Financial data: no GPS false positives",
        message: "ASML revenue EUR 7.3856 billion, EPS 5.12340, P/E 34.5678, stock 654.3200",
        realValues: [],
        checkLlmSees: ["654.3200"],  // must not be obfuscated as GPS
      },
      // Channel deobfuscation test — verifies message_sending hook fires
      {
        name: "Channel deobfuscation: message_sending hook fires",
        message: "Format as JSON: admin@internal-corp.net",
        realValues: ["admin@internal-corp.net"],
        checkMessageSending: true,
      },
      // Slack E2E: full gateway → mock LLM → Slack delivery
      {
        name: "Slack E2E: email round-trip via Slack HTTP",
        slackE2E: true,
        message: "echo this back to me please: admin@internal-corp.net",
        realValues: ["admin@internal-corp.net"],
      },
      // Slack E2E: public URL must pass through (not obfuscated)
      {
        name: "Slack E2E: public URL passes through",
        slackE2E: true,
        message: "have a look at https://www.npmjs.com/package/shroud-privacy",
        realValues: [],  // URL is public — should NOT be obfuscated
        checkUrlPassthrough: "npmjs.com",
      },
      // Slack E2E: workspace file paths must not be obfuscated
      {
        name: "Slack E2E: workspace paths pass through",
        slackE2E: true,
        message: "run python3 /home/user/.openclaw/workspace/scripts/searxng_search.py and save to /tmp/results.json",
        realValues: [],
        checkPathPassthrough: ["/home/user/.openclaw/workspace/scripts/searxng_search.py", "/tmp/results.json"],
      },
      // Multi-turn test — verifies deobfuscated assistant messages don't leak
      // real PII to the LLM on subsequent turns
      {
        name: "Multi-turn: no PII leak from deobfuscated history",
        multiTurn: true,
        turns: [
          { message: "Format as JSON: admin@internal-corp.net", realValues: ["admin@internal-corp.net"] },
          { message: "Now format as JSON: ops@internal-corp.net", realValues: ["admin@internal-corp.net", "ops@internal-corp.net"] },
        ],
      },
      // Compaction-aware multi-turn: many turns with diverse PII to stress
      // the re-obfuscation path after OC compacts earlier messages
      {
        name: "Multi-turn compaction: 4 turns with mixed PII types",
        multiTurn: true,
        turns: [
          { message: "Server at 172.16.5.10 needs a restart, contact noc@infra-corp.net", realValues: ["172.16.5.10", "noc@infra-corp.net"] },
          { message: "BGP peer 10.255.0.1 AS 64512 is also flapping", realValues: ["172.16.5.10", "noc@infra-corp.net", "10.255.0.1"] },
          { message: "Escalate to +15550101002 about the outage on 10.255.0.1", realValues: ["172.16.5.10", "noc@infra-corp.net", "10.255.0.1", "+15550101002"] },
          { message: "Also notify ops@infra-corp.net about 192.168.1.50 being down", realValues: ["172.16.5.10", "noc@infra-corp.net", "10.255.0.1", "+15550101002", "ops@infra-corp.net", "192.168.1.50"] },
        ],
      },
      {
        name: "Multi-turn compaction: credentials across turns",
        multiTurn: true,
        turns: [
          { message: "Server 10.0.2.10 has enable secret 5 $1$xyz$SecretHash", realValues: ["10.0.2.10"] },
          { message: "Also check 10.0.2.11 with API key SHROUD_TEST_ANTHROPIC_KEY", realValues: ["10.0.2.10", "10.0.2.11", "SHROUD_TEST_ANTHROPIC_KEY"] },
          { message: "Send report to admin@secret-corp.com about both servers", realValues: ["10.0.2.10", "10.0.2.11", "admin@secret-corp.com"] },
        ],
      },
      {
        name: "Multi-turn compaction: network config accumulation",
        multiTurn: true,
        turns: [
          { message: "hostname CORE-RTR-01\nenable secret 5 $1$mERo$ILwq", realValues: ["CORE-RTR-01"] },
          { message: "Add neighbor 10.1.0.2 remote-as 65002 with password BgpS3cret", realValues: ["CORE-RTR-01", "10.1.0.2", "BgpS3cret"] },
          { message: "Set snmp-server community Pr1vRW RW and host 10.10.5.30", realValues: ["CORE-RTR-01", "10.1.0.2", "BgpS3cret", "Pr1vRW", "10.10.5.30"] },
        ],
      },
      // ── Extended multi-turn compaction scenarios ──
      // These exercise deep conversation history, PII accumulation across
      // many turns, and diverse entity types to stress re-obfuscation
      // after OpenClaw compacts earlier messages.
      {
        name: "Multi-turn: 6-turn PII accumulation stress test",
        multiTurn: true,
        turns: [
          { message: "Server 10.20.30.40 is reporting disk failures", realValues: ["10.20.30.40"] },
          { message: "Contact noc-lead@datacenter-ops.net about it", realValues: ["10.20.30.40", "noc-lead@datacenter-ops.net"] },
          { message: "Also page the on-call at +15550101003", realValues: ["10.20.30.40", "noc-lead@datacenter-ops.net", "+15550101003"] },
          { message: "The backup server is at 172.31.255.10", realValues: ["10.20.30.40", "noc-lead@datacenter-ops.net", "+15550101003", "172.31.255.10"] },
          { message: "Failover API key is SHROUD_TEST_OPENAI_KEY", realValues: ["10.20.30.40", "noc-lead@datacenter-ops.net", "+15550101003", "172.31.255.10", "SHROUD_TEST_OPENAI_KEY"] },
          { message: "Send incident report to postmortem@datacenter-ops.net", realValues: ["10.20.30.40", "noc-lead@datacenter-ops.net", "+15550101003", "172.31.255.10", "SHROUD_TEST_OPENAI_KEY", "postmortem@datacenter-ops.net"] },
        ],
      },
      {
        name: "Multi-turn: same PII repeated across turns tests determinism",
        multiTurn: true,
        turns: [
          { message: "Check the firewall at 10.99.1.1 for blocked traffic from ops@shared-infra.net", realValues: ["10.99.1.1", "ops@shared-infra.net"] },
          { message: "The issue on 10.99.1.1 is confirmed, ops@shared-infra.net needs to investigate", realValues: ["10.99.1.1", "ops@shared-infra.net"] },
          { message: "Final update: 10.99.1.1 resolved. Notify ops@shared-infra.net and sec-team@shared-infra.net", realValues: ["10.99.1.1", "ops@shared-infra.net", "sec-team@shared-infra.net"] },
        ],
      },
      {
        name: "Multi-turn: mixed category per turn (email, IP, credential, IBAN, phone)",
        multiTurn: true,
        turns: [
          { message: "Billing contact is finance@acme-billing.com", realValues: ["finance@acme-billing.com"] },
          { message: "Payment gateway at 10.88.2.100 is timing out", realValues: ["finance@acme-billing.com", "10.88.2.100"] },
          { message: "Gateway API key is SHROUD_TEST_ANTHROPIC_KEY", realValues: ["finance@acme-billing.com", "10.88.2.100", "SHROUD_TEST_ANTHROPIC_KEY"] },
          { message: "Refund to IBAN DE89370400440532013000 for order 7789", realValues: ["finance@acme-billing.com", "10.88.2.100", "SHROUD_TEST_ANTHROPIC_KEY", "DE89370400440532013000"] },
          { message: "Call the merchant at +15550101004 to confirm", realValues: ["finance@acme-billing.com", "10.88.2.100", "SHROUD_TEST_ANTHROPIC_KEY", "DE89370400440532013000", "+15550101004"] },
        ],
      },
      {
        name: "Multi-turn: network config with propagating hostname (4 turns, 9 PII)",
        multiTurn: true,
        turns: [
          { message: "hostname LAX-DIST-RTR-02\ninterface GigabitEthernet0/0\n ip address 10.40.1.1 255.255.255.252", realValues: ["LAX-DIST-RTR-02", "10.40.1.1"] },
          { message: "router bgp 65100\n neighbor 10.40.1.2 remote-as 65200\n neighbor 10.40.1.2 password 7 14141B180F0B", realValues: ["LAX-DIST-RTR-02", "10.40.1.1", "10.40.1.2", "14141B180F0B"] },
          { message: "snmp-server community N3tM0nRO RO\nsnmp-server community N3tM0nRW RW\nsnmp-server host 10.40.5.50 version 2c N3tM0nRO", realValues: ["LAX-DIST-RTR-02", "10.40.1.1", "10.40.1.2", "14141B180F0B", "N3tM0nRO", "N3tM0nRW", "10.40.5.50"] },
          { message: "Contact neteng@isp-partner.net about the peering config for LAX-DIST-RTR-02", realValues: ["LAX-DIST-RTR-02", "10.40.1.1", "10.40.1.2", "14141B180F0B", "N3tM0nRO", "N3tM0nRW", "10.40.5.50", "neteng@isp-partner.net"] },
        ],
      },
      {
        name: "Multi-turn: long message compaction pressure (18+ entities)",
        multiTurn: true,
        turns: [
          { message: "hostname BULK-TEST-RTR-01\ninterface Loopback0\n ip address 10.250.0.1 255.255.255.255", realValues: ["BULK-TEST-RTR-01", "10.250.0.1"] },
          {
            message: "Full WAN config:\nrouter bgp 65500\n neighbor 10.60.1.1 remote-as 65501\n neighbor 10.60.1.1 password 7 02050D480809\n neighbor 10.60.1.2 remote-as 65502\n neighbor 10.60.1.2 password 7 02050D480809\n neighbor 10.60.1.3 remote-as 65503\n neighbor 10.60.1.3 password 7 02050D480809\n!\nsnmp-server community BulkRO1 RO\nsnmp-server community BulkRW1 RW\nsnmp-server host 10.60.10.1 version 2c BulkRO1\nsnmp-server host 10.60.10.2 version 2c BulkRO1\n!\nlogging host 10.60.20.1\nlogging host 10.60.20.2\n!\nenable secret 5 $1$Bulk$HashValue99\n!\nContact infra-bulk@wan-ops.net for issues",
            realValues: [
              "BULK-TEST-RTR-01", "10.250.0.1",
              "10.60.1.1", "10.60.1.2", "10.60.1.3", "02050D480809",
              "BulkRO1", "BulkRW1", "10.60.10.1", "10.60.10.2",
              "10.60.20.1", "10.60.20.2",
              "infra-bulk@wan-ops.net",
            ],
          },
          {
            message: "Summarize the peering config and send to netops@wan-ops.net",
            realValues: [
              "BULK-TEST-RTR-01", "10.250.0.1",
              "10.60.1.1", "10.60.1.2", "10.60.1.3", "02050D480809",
              "BulkRO1", "BulkRW1", "10.60.10.1", "10.60.10.2",
              "10.60.20.1", "10.60.20.2",
              "infra-bulk@wan-ops.net", "netops@wan-ops.net",
            ],
          },
        ],
      },
      {
        name: "Multi-turn: AWS credentials and cloud PII across turns",
        multiTurn: true,
        turns: [
          { message: "Staging DB at 10.70.3.5 needs credential rotation", realValues: ["10.70.3.5"] },
          { message: "AWS access key for CI is SHROUD_TEST_AWS_ACCESS_KEY and prod DB is 10.70.3.10", realValues: ["10.70.3.5", "SHROUD_TEST_AWS_ACCESS_KEY", "10.70.3.10"] },
          { message: "Alert devops-oncall@platform-team.io about the rotation", realValues: ["10.70.3.5", "SHROUD_TEST_AWS_ACCESS_KEY", "10.70.3.10", "devops-oncall@platform-team.io"] },
        ],
      },
      // NOTE: Slack gateway E2E test removed — OpenClaw's Slack extension
      // cannot start with fake tokens in a test sandbox. The Slack flow is
      // tested by 5 unit tests in hooks.test.ts (hooks - Slack E2E simulation)
      // that verify: mailto stripping, assistant re-obfuscation, message_sending
      // deobfuscation, and full flow with no fake leakage.
      // Stats & logging verification
      // Audit & stats verification
      {
        name: "Audit log emitted with proof hashes",
        message: "Check 10.42.88.7 and admin@example-corp.com",
        realValues: ["10.42.88.7", "admin@example-corp.com"],
        expectObfuscated: 2,
        checkAudit: true,
      },
      {
        name: "Stats file written after obfuscation",
        message: "The server db.prod.internal at 172.16.0.50 needs a reboot",
        realValues: ["172.16.0.50"],
        checkStats: true,
      },
    ];

    // Channel E2E tests that need the gateway
    all.push(
        // ── Slack channel/user simulation ──
        {
          name: "Slack E2E: user in #network-ops channel sends PII",
          slackE2E: true,
          slackChannel: "C00000001",
          slackUser: "U00000001",
          message: "Switch at 10.200.1.5 is down, contact admin@noc.internal for help",
          realValues: ["10.200.1.5", "admin@noc.internal"],
        },
        {
          name: "Slack E2E: different user in #security-alerts channel",
          slackE2E: true,
          slackChannel: "C00000002",
          slackUser: "U00000002",
          message: "Incident: unauthorized login from 192.168.5.22 by user john@acme-corp.net",
          realValues: ["192.168.5.22", "john@acme-corp.net"],
        },
        // ── Deob round-trip via Slack (echo mode: LLM echoes obfuscated text, Slack gets real values) ──
        {
          name: "Slack Deob: email + IP round-trip",
          slackE2E: true,
          message: "Contact admin@internal-corp.net about server 10.42.88.7",
          realValues: ["admin@internal-corp.net", "10.42.88.7"],
        },
        {
          name: "Slack Deob: BGP config round-trip",
          slackE2E: true,
          message: "neighbor 10.0.0.2 remote-as 65002 password 7 070C285F4D06",
          realValues: ["10.0.0.2", "070C285F4D06"],
        },
        {
          name: "Slack Deob: multi-entity round-trip",
          slackE2E: true,
          message: "ALERT: 10.50.1.1 down. Contact ops@noc.internal, host DAL-CORE-RTR-01",
          realValues: ["10.50.1.1", "ops@noc.internal", "DAL-CORE-RTR-01"],
        },
        {
          name: "Slack Deob: IBAN round-trip",
          slackE2E: true,
          message: "Wire payment to AT611904300234573201 for invoice 4412",
          realValues: ["AT611904300234573201"],
        },
        // ── WhatsApp E2E ──
        {
          name: "WhatsApp E2E: inbound message with PII obfuscated",
          whatsAppE2E: true,
          whatsAppFrom: "+353850000001",
          message: "Server db.prod.internal at 172.16.0.50 is unreachable, call +15550101002",
          realValues: ["172.16.0.50", "+15550101002"],
        },
        // ── Cron E2E ──
        {
          name: "Cron E2E: scheduled job fires with PII obfuscation",
          cronE2E: true,
          realValues: ["172.16.0.50"],
          cronTimeoutMs: 90000,
        },
    );

    // Load scenarios from JSON files in scenarios/ directory
    const scenarioDir = resolve(import.meta.dirname, "scenarios");
    try {
      const files = ["docker-e2e-regression.json"];
      for (const file of files) {
        const filePath = join(scenarioDir, file);
        if (!existsSync(filePath)) continue;
        const raw = JSON.parse(readFileSync(filePath, "utf-8"));
        const scenarios = Array.isArray(raw) ? raw : [];
        for (const s of scenarios) {
          all.push({
            name: s.name,
            message: s.input,
            realValues: s.assertions?.llm_must_not_see || [],
            checkLlmSees: s.assertions?.llm_must_see || [],
            checkDeobfuscation: s.assertions?.check_deobfuscation || false,
            checkStats: false,
            checkAudit: false,
          });
        }
      }
    } catch {}

    // ── Sandbox exec scenarios (only when SHROUD_TEST_SANDBOX=1) ──
    if (process.env.SHROUD_TEST_SANDBOX === "1") {
      all.push(
        {
          name: "Sandbox exec: PII obfuscated in tool call params",
          message: "Look up the DNS record for server 10.42.88.7 and email admin@sandbox-corp.net about it",
          realValues: ["10.42.88.7", "admin@sandbox-corp.net"],
        },
        {
          name: "Sandbox exec: workspace path passthrough in sandbox",
          message: "Run python3 /home/node/scripts/check.py on 172.16.5.10",
          realValues: ["172.16.5.10"],
          checkLlmSees: ["/home/node/scripts/check.py"],
        },
        {
          name: "Sandbox exec: multi-turn with exec context",
          multiTurn: true,
          turns: [
            { message: "Check disk on 10.50.2.1 and report to sysadmin@infra-ops.net", realValues: ["10.50.2.1", "sysadmin@infra-ops.net"] },
            { message: "Now check the backup at 10.50.2.2 and CC security@infra-ops.net", realValues: ["10.50.2.1", "sysadmin@infra-ops.net", "10.50.2.2", "security@infra-ops.net"] },
          ],
        },
        {
          name: "Sandbox exec: credentials in exec context",
          message: "Connect to postgresql://admin:S3cretPass@10.0.5.20:5432/prod and run VACUUM",
          realValues: ["10.0.5.20"],
        },
        {
          name: "Sandbox exec: network config via exec",
          message: "hostname SBX-RTR-01\ninterface GigabitEthernet0/1\n ip address 10.80.1.1 255.255.255.0\n!\nrouter bgp 65400\n neighbor 10.80.1.2 remote-as 65401",
          realValues: ["SBX-RTR-01", "10.80.1.1", "10.80.1.2"],
        },
        {
          name: "Sandbox exec: API key in sandboxed tool call",
          message: "Use API key SHROUD_TEST_ANTHROPIC_KEY to query the endpoint at 10.90.0.5",
          realValues: ["SHROUD_TEST_ANTHROPIC_KEY", "10.90.0.5"],
        },
        {
          name: "Sandbox exec: IBAN in sandboxed financial tool",
          message: "Process refund to IBAN AT611904300234573201 and notify finance@sandbox-corp.net",
          realValues: ["AT611904300234573201", "finance@sandbox-corp.net"],
        },
        {
          name: "Sandbox exec: Slack upload from sandbox",
          slackE2E: true,
          message: "Generate a report about server 10.42.88.7 and upload it to this channel",
          realValues: ["10.42.88.7"],
        },
      );
    }

    if (this.scenario) {
      return all.filter(s => s.name.toLowerCase().includes(this.scenario.toLowerCase()));
    }
    return all;
  }


  async _waitFor(checkFn, timeoutMs, description, proc) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (proc && proc.exitCode !== null) {
        throw new Error(`Process exited (code ${proc.exitCode}) while waiting for ${description}`);
      }
      if (await checkFn()) return;
      await new Promise(r => setTimeout(r, 300));
    }
    throw new Error(`Timeout waiting for ${description} (${timeoutMs}ms)`);
  }

  _agentEnv() {
    return {
      PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
      NODE_PATH: process.env.NODE_PATH || "",
      OPENCLAW_STATE_DIR: this.stateDir,
      OPENCLAW_CONFIG_PATH: join(this.stateDir, "openclaw.json"),
      OPENCLAW_NO_RESPAWN: "1",
      OPENCLAW_SKIP_CHANNELS: "1",
      OPENCLAW_SKIP_CRON: "1",
      OPENCLAW_LOG_LEVEL: "info",
      SHROUD_STATS_FILE: join(this.stateDir, "shroud-stats.json"),
      ANTHROPIC_API_KEY: "SHROUD_TEST_ANTHROPIC_KEY",
      OPENAI_API_KEY: "sk-sandbox-dummy",
      HOME: tmpdir(),
      NODE_ENV: "test",
      LANG: process.env.LANG || "en_US.UTF-8",
      TERM: process.env.TERM || "xterm-256color",
    };
  }

  _getOpenClawBin() {
    return process.env.OPENCLAW_BIN || "openclaw";
  }

  // ── HTTP helper ───────────────────────────────────────────

  _httpReq(method, url, body, extraHeaders, rawBody) {
    return new Promise((res, reject) => {
      const u = new URL(url);
      const req = http.request(
        { hostname: u.hostname, port: u.port, path: u.pathname, method, headers: { "Content-Type": "application/json", ...extraHeaders } },
        (resp) => {
          const chunks = [];
          resp.on("data", c => chunks.push(c));
          resp.on("end", () => {
            const raw = Buffer.concat(chunks).toString();
            try { res(JSON.parse(raw)); } catch { res(raw); }
          });
        },
      );
      req.on("error", reject);
      const toWrite = rawBody || (body ? (typeof body === "string" ? body : JSON.stringify(body)) : null);
      if (toWrite) req.write(toWrite);
      req.end();
    });
  }

  // ── Cleanup ───────────────────────────────────────────────

  async _teardown() {
    if (this.gatewayProc && !this.gatewayProc.killed) {
      try { this.gatewayProc.kill("SIGTERM"); } catch {}
    }
    if (this.mockLlmProc && !this.mockLlmProc.killed) {
      try { this.mockLlmProc.kill("SIGTERM"); } catch {}
    }
    if (this.mockSlackProc && !this.mockSlackProc.killed) {
      try { this.mockSlackProc.kill("SIGTERM"); } catch {}
    }
    if (this.mockSlack443Proc && !this.mockSlack443Proc.killed) {
      try { this.mockSlack443Proc.kill("SIGTERM"); } catch {}
    }
    if (this.mockWhatsAppProc && !this.mockWhatsAppProc.killed) {
      try { this.mockWhatsAppProc.kill("SIGTERM"); } catch {}
    }
  }

  _log(msg) {
    console.log(msg);
  }
}
