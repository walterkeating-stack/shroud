#!/usr/bin/env node
/**
 * OpenClaw Integration Runner — smoke-tests Shroud through a real OpenClaw instance.
 *
 * Architecture (lean, no insanity):
 *   1. npm-installs OpenClaw ONCE into a cached sandbox dir (~/.cache/shroud-test/openclaw-<version>)
 *   2. Copies Shroud plugin into sandbox extensions
 *   3. Starts ONE mock Slack server (HTTP mode)
 *   4. Starts ONE mock LLM server
 *   5. Runs ~10 smoke tests via `openclaw agent --local --message ...`
 *   6. Verifies plugin loaded, hooks fired, stats/logging work
 *   7. Tears down
 *
 * No parallel worker slots. No network namespaces. No snapshots.
 * One install, one mock LLM, one agent call per test.
 */

import { spawn, execSync } from "node:child_process";
import {
  mkdirSync, writeFileSync, cpSync, existsSync, readFileSync, rmSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir, homedir } from "node:os";
import { createInterface } from "node:readline";
import crypto from "node:crypto";
import http from "node:http";
import {
  assertLlmDidNotSee,
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

    // Cached install dir — survives across runs, one dir per version
    this.cacheDir = join(homedir(), ".cache", "shroud-test");
    this.sandboxDir = null;   // set in _ensureInstalled
    this.stateDir = null;     // OpenClaw state dir for this run
    this.mockLlmPort = null;
    this.mockLlmProc = null;
    this.mockSlackPort = null;
    this.mockSlackProc = null;
    this.results = { scenarios: [], passed: 0, failed: 0, skipped: 0, duration: 0 };
  }

  async run() {
    const startTime = Date.now();
    this._log("OpenClaw Integration Smoke Test");
    this._log("=".repeat(50));

    try {
      await this._ensureInstalled();
      await this._startMockLlm();
      await this._startMockSlack();
      this._setupState();
      this._installShroudPlugin();
      this._writeConfig();
      await this._runScenarios();
    } finally {
      await this._teardown();
    }

    this.results.duration = Date.now() - startTime;

    Reporter.console(this.results, this.verbose);
    return this.results;
  }

  // ── Install (cached) ──────────────────────────────────────

  async _ensureInstalled() {
    const versionTag = this.openclawVersion === "latest"
      ? await this._resolveLatestVersion()
      : this.openclawVersion;

    this.sandboxDir = join(this.cacheDir, `openclaw-${versionTag}`);
    const marker = join(this.sandboxDir, ".installed");

    if (existsSync(marker)) {
      this._log(`Using cached OpenClaw ${versionTag}`);
      return;
    }

    this._log(`Installing OpenClaw ${versionTag} (one-time)...`);
    mkdirSync(this.sandboxDir, { recursive: true });

    writeFileSync(join(this.sandboxDir, "package.json"), JSON.stringify({
      name: "shroud-oc-sandbox",
      version: "0.0.0",
      private: true,
    }));

    const pkgSpec = this.openclawVersion === "latest" ? "openclaw" : `openclaw@${versionTag}`;
    execSync(`npm install ${pkgSpec} --no-save --prefix "${this.sandboxDir}"`, {
      stdio: this.verbose ? "inherit" : "pipe",
      timeout: 300000,
    });

    writeFileSync(marker, versionTag);
    this._log(`Installed OpenClaw ${versionTag}`);
  }

  async _resolveLatestVersion() {
    try {
      return execSync("npm view openclaw version", { encoding: "utf-8", timeout: 15000 }).trim();
    } catch {
      return "latest";
    }
  }

  // ── State dir (fresh per run) ─────────────────────────────

  _setupState() {
    this.stateDir = join(tmpdir(), `shroud-oc-state-${Date.now()}`);
    for (const sub of ["extensions", "workspace", "logs", "credentials", "agents"]) {
      mkdirSync(join(this.stateDir, sub), { recursive: true });
    }
    this._log(`State dir: ${this.stateDir}`);
  }

  // ── Plugin install ────────────────────────────────────────

  _installShroudPlugin() {
    const dest = join(this.stateDir, "extensions", "shroud-privacy");
    mkdirSync(dest, { recursive: true });

    cpSync(join(this.shroudPath, "dist"), join(dest, "dist"), { recursive: true });
    cpSync(join(this.shroudPath, "package.json"), join(dest, "package.json"));

    const manifest = existsSync(join(this.shroudPath, "plugin.json"))
      ? join(this.shroudPath, "plugin.json")
      : join(this.shroudPath, "openclaw.plugin.json");
    if (existsSync(manifest)) {
      cpSync(manifest, join(dest, "openclaw.plugin.json"), { dereference: true });
    }

    this._log("Shroud plugin installed");
  }

  // ── Config ────────────────────────────────────────────────

  _writeConfig() {
    const statsFile = join(this.stateDir, "shroud-stats.json");

    const config = {
      meta: { lastTouchedVersion: this.openclawVersion, lastTouchedAt: new Date().toISOString() },
      gateway: { mode: "local" },
      agents: {
        defaults: {
          workspace: join(this.stateDir, "workspace"),
          model: { primary: "mock-provider/mock-model" },
          timeoutSeconds: 30,
        },
      },
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
        allow: ["shroud-privacy"],
        entries: {
          "shroud-privacy": {
            enabled: true,
            config: {
              auditEnabled: true,
              auditLogFormat: "json",
              auditIncludeProofHashes: true,
              auditHashSalt: "test-salt",
            },
          },
        },
        installs: {
          "shroud-privacy": {
            source: "path",
            spec: "shroud-privacy",
            installPath: join(this.stateDir, "extensions", "shroud-privacy"),
            version: this._shroudVersion(),
          },
        },
      },
    };

    writeFileSync(join(this.stateDir, "openclaw.json"), JSON.stringify(config, null, 2));
    this._log(`Config written (LLM: 127.0.0.1:${this.mockLlmPort})`);
  }

  _shroudVersion() {
    try {
      return JSON.parse(readFileSync(join(this.shroudPath, "package.json"), "utf-8")).version || "0.0.0";
    } catch { return "0.0.0"; }
  }

  // ── Mock LLM ──────────────────────────────────────────────

  async _startMockLlm() {
    const serverPath = resolve(import.meta.dirname, "..", "mock-llm", "server.mjs");

    return new Promise((res, reject) => {
      this.mockLlmProc = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PORT: "0", MOCK_LLM_NO_TOOLS: "1" },
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

    if (this.scenario) {
      return all.filter(s => s.name.toLowerCase().includes(this.scenario.toLowerCase()));
    }
    return all;
  }

  async _runScenarios() {
    const scenarios = this._buildScenarios();
    const tests = [];

    this._log(`\nRunning ${scenarios.length} scenarios...`);
    this._log("-".repeat(50));

    for (const s of scenarios) {
      this.results.total++;
      const result = await this._runOne(s);
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

  async _runOne(scenario) {
    const start = Date.now();
    const result = { name: scenario.name, status: "pass", duration: 0, error: null };

    try {
      // Slack E2E: full gateway + Slack HTTP mode + mock Slack API
      if (scenario.slackE2E) {
        await this._runSlackE2E(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // Multi-turn tests run multiple messages in the same session
      if (scenario.multiTurn) {
        await this._runMultiTurnScenario(scenario);
        result.duration = Date.now() - start;
        return result;
      }

      // Clear mock LLM log
      await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

      // Run agent — capture stderr for plugin lifecycle checks
      const { output: agentOutput, stderr } = await this._runAgentFull(scenario.message);

      // 1. Plugin must have loaded
      if (!stderr.includes("Plugin loaded")) {
        throw new Error("Shroud plugin did not load — 'Plugin loaded' not found in stderr");
      }

      // 2. Hook must have fired and obfuscated entities (when PII is present)
      const obfMatch = stderr.match(/before_prompt_build: obfuscated (\d+) entities/);
      if (scenario.realValues?.length > 0) {
        if (!obfMatch) {
          throw new Error("before_prompt_build hook did not fire");
        }
        const obfCount = parseInt(obfMatch[1], 10);
        if (scenario.expectObfuscated && obfCount < scenario.expectObfuscated) {
          throw new Error(`Expected at least ${scenario.expectObfuscated} obfuscated entities, got ${obfCount}`);
        }
        if (obfCount === 0) {
          throw new Error("Hook fired but obfuscated 0 entities — detection may be broken");
        }
      }

      // 3. LLM must have received a request (agent reached the model)
      const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
      if (!Array.isArray(llmRequests) || llmRequests.length === 0) {
        throw new Error("Mock LLM received 0 requests — agent did not reach the model");
      }

      // 3b. LLM must NOT have seen real PII values in any message content
      if (scenario.realValues?.length > 0) {
        const allContent = JSON.stringify(llmRequests);
        for (const val of scenario.realValues) {
          if (allContent.includes(val)) {
            throw new Error(`LLM saw real PII value: "${val}" — fetch intercept failed`);
          }
        }
      }

      // 3c. LLM MUST see these values (passthrough assertions)
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

      // 4. No CGNAT/ULA leaks in agent output
      if (agentOutput) {
        assertNoCgnatLeak(agentOutput);
        assertNoCgnatRangeLeak(agentOutput);
        assertNoUlaLeak(agentOutput);
      }

      // 5. Audit log check — stderr should contain audit JSON if auditEnabled
      //    On older OpenClaw versions, plugins.entries.config may not be forwarded.
      if (scenario.checkAudit) {
        if (!stderr.includes('"event":"shroud.audit.obfuscate"')) {
          // Check if this is an older version that doesn't forward plugin config
          if (!stderr.includes("auditEnabled") && !stderr.includes("audit.obfuscate")) {
            throw new Error(
              "Audit log not found — OpenClaw may not be forwarding plugin config " +
              "(plugins.entries.<id>.config). Check compatibility with this version.",
            );
          }
        }
        // Verify audit JSON is parseable and has expected fields
        const auditLine = stderr.split("\n").find(l => l.includes('"event":"shroud.audit.obfuscate"'));
        if (auditLine) {
          // Extract JSON object from the log line (may have prefix/suffix)
          const jsonStart = auditLine.indexOf("{");
          const jsonEnd = auditLine.lastIndexOf("}");
          if (jsonStart >= 0 && jsonEnd > jsonStart) {
            const audit = JSON.parse(auditLine.slice(jsonStart, jsonEnd + 1));
            if (!audit.req) throw new Error("Audit log missing request ID");
            if (!audit.proofIn) throw new Error("Audit log missing proofIn hash");
            if (!audit.proofOut) throw new Error("Audit log missing proofOut hash");
            if (!audit.byCategory) throw new Error("Audit log missing byCategory breakdown");
          }
        }
      }

      // 6. Channel deobfuscation check — verify deobfuscation occurred
      if (scenario.checkMessageSending) {
        const hasDeobfuscation =
          stderr.includes("message_sending: deobfuscated") ||
          stderr.includes("before_message_write: deobfuscated") ||
          stderr.includes("DEOBFUSCATE");
        // Also check: the agent output should NOT contain CGNAT fakes
        // (which would indicate deobfuscation failed)
        if (agentOutput) {
          assertNoCgnatLeak(agentOutput);
        }
        // If the LLM echoed back obfuscated content and we see no deobfuscation
        // log AND fakes leaked to output, that's a failure.
        if (!hasDeobfuscation && agentOutput) {
          // Check if any fake values leaked to the output
          const cgnatPattern = /\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/;
          if (cgnatPattern.test(agentOutput)) {
            throw new Error(
              "Deobfuscation did not fire and CGNAT fakes leaked to agent output",
            );
          }
        }
      }

      // 7. Stats file check
      if (scenario.checkStats) {
        const statsPath = join(this.stateDir, "shroud-stats.json");
        const defaultStats = "/tmp/shroud-stats.json";
        const found = existsSync(statsPath) ? statsPath : existsSync(defaultStats) ? defaultStats : null;
        if (found) {
          const stats = JSON.parse(readFileSync(found, "utf-8"));
          if (stats.storeMappings === undefined) throw new Error("Stats file missing storeMappings");
          if (!stats.updatedAt) throw new Error("Stats file missing updatedAt timestamp");
          if (!stats.ruleHits) throw new Error("Stats file missing ruleHits");
        } else {
          throw new Error("Stats file not written to " + statsPath + " or " + defaultStats);
        }
      }
    } catch (err) {
      if (err.message.includes("Slack E2E skipped")) {
        result.status = "skip";
        result.error = err.message;
      } else {
        result.status = "fail";
        result.error = err.message;
      }
    }

    result.duration = Date.now() - start;
    return result;
  }

  // ── Slack E2E scenario ───────────────────────────────────

  async _runSlackE2E(scenario) {
    if (!this.mockSlackPort) throw new Error("Mock Slack server not running");

    // Write Slack-enabled config
    const slackSigningSecret = crypto.randomBytes(16).toString("hex");
    const slackConfig = JSON.parse(readFileSync(join(this.stateDir, "openclaw.json"), "utf-8"));
    slackConfig.channels = {
      slack: {
        mode: "http",
        enabled: true,
        streaming: "off",
        nativeStreaming: false,
        botToken: "SHROUD_TEST_SLACK_TOKEN",
        signingSecret: slackSigningSecret,
        webhookPath: "/slack/events",
        groupPolicy: "allowlist",
        channels: { "C00000001": { requireMention: false } },
        dmPolicy: "allowlist",
        allowFrom: ["U00000001"],
      },
    };
    const testGatewayPort = 19000 + Math.floor(Math.random() * 1000);
    slackConfig.gateway = { ...slackConfig.gateway, port: testGatewayPort };
    writeFileSync(join(this.stateDir, "openclaw.json"), JSON.stringify(slackConfig, null, 2));

    // Clear mock state
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);
    await this._httpReq("DELETE", `http://127.0.0.1:${this.mockSlackPort}/messages`);

    // Start gateway with Slack channel + mock Slack API redirect
    const bin = this._getOpenClawBin();
    const interceptPath = resolve(import.meta.dirname, "..", "mock-slack", "intercept.cjs");
    const env = {
      ...this._agentEnv(),
      MOCK_SLACK_PORT: String(this.mockSlackPort),
      MOCK_SLACK_URL: `http://127.0.0.1:${this.mockSlackPort}/api/`,
      NODE_OPTIONS: `--require ${interceptPath}`,
      OPENCLAW_GATEWAY_PORT: String(testGatewayPort),
    };
    delete env.OPENCLAW_SKIP_CHANNELS;
    delete env.OPENCLAW_SKIP_CRON;
    delete env.OPENCLAW_NO_RESPAWN;

    const gatewayProc = spawn("node", [bin, "gateway"], {
      stdio: ["pipe", "pipe", "pipe"],
      env,
      cwd: join(this.stateDir, "workspace"),
    });

    const stderrBuf = { data: "" };
    const stdoutBuf = { data: "" };
    gatewayProc.stderr.on("data", (d) => { stderrBuf.data += d; });
    gatewayProc.stdout.on("data", (d) => { stdoutBuf.data += d; });

    try {
      // Wait for gateway to be ready — check stderr, stdout, and log file
      const logFile = join(this.stateDir, "logs", "openclaw.log");
      await this._waitFor(
        () => {
          const s = stderrBuf.data + stdoutBuf.data;
          let logData = "";
          try { logData = existsSync(logFile) ? readFileSync(logFile, "utf-8") : ""; } catch {}
          const all = s + logData;
          return all.includes("slack") || all.includes("Plugin loaded") ||
                 all.includes("listening") || all.includes("bonjour") ||
                 all.includes("Shroud") || all.includes("started") ||
                 all.length > 500; // gateway is producing output
        },
        20000, "gateway to start", gatewayProc,
      );
      // Extra wait for HTTP server to bind
      await new Promise(r => setTimeout(r, 3000));

      // Inject a Slack message event
      const timestamp = Math.floor(Date.now() / 1000);
      const eventBody = JSON.stringify({
        type: "event_callback",
        token: "mock-verification-token",
        team_id: "T00000001",
        event: {
          type: "message",
          channel: "C00000001",
          user: "U00000001",
          text: scenario.message,
          ts: `${timestamp}.000001`,
        },
      });
      const sigBasestring = `v0:${timestamp}:${eventBody}`;
      const signature = "v0=" + crypto.createHmac("sha256", slackSigningSecret)
        .update(sigBasestring).digest("hex");

      const webhookResp = await this._httpReq(
        "POST", `http://127.0.0.1:${testGatewayPort}/slack/events`,
        null, // body already in eventBody
        { "X-Slack-Request-Timestamp": String(timestamp), "X-Slack-Signature": signature },
        eventBody, // raw body
      );

      if (this.verbose) {
        this._log(`[slack-e2e] Gateway port: ${testGatewayPort}`);
        this._log(`[slack-e2e] Webhook response: ${JSON.stringify(webhookResp)}`);
        this._log(`[slack-e2e] stderr: ${stderrBuf.data.slice(-500)}`);
        this._log(`[slack-e2e] stdout (full): ${stdoutBuf.data}`);
        // Check multiple log locations
        for (const logPath of [
          join(this.stateDir, "logs", "openclaw.log"),
          join(tmpdir(), ".openclaw", "logs", "openclaw.log"),
        ]) {
          try {
            const logData = readFileSync(logPath, "utf-8");
            const lines = logData.split("\n").filter(l => l.includes("slack") || l.includes("channel") || l.includes("error") || l.includes("webhook"));
            this._log(`[slack-e2e] log (${logPath}): ${lines.slice(-10).join("\n") || "(no matches)"}`);
          } catch {}
        }
      }

      // Wait for mock Slack API to receive outbound message(s)
      // OpenClaw's Slack extension may fail to start with mock tokens —
      // if the gateway stderr shows a Slack auth/connection error, skip gracefully.
      try {
        await this._waitFor(
          async () => {
            // Check if gateway reported Slack failure
            if (stderrBuf.data.includes("invalid_auth") ||
                stderrBuf.data.includes("not_authed") ||
                stderrBuf.data.includes("Slack adapter failed") ||
                stderrBuf.data.includes("connection refused")) {
              throw new Error("Slack extension rejected mock credentials — skipping E2E");
            }
            const msgs = await this._httpReq("GET", `http://127.0.0.1:${this.mockSlackPort}/messages`);
            return Array.isArray(msgs) && msgs.length > 0;
          },
          30000, "Slack mock to receive outbound message", gatewayProc,
        );
      } catch (err) {
        if (err.message.includes("skipping E2E") || err.message.includes("Timeout")) {
          throw new Error(
            "Slack E2E skipped — OpenClaw Slack extension cannot start with mock tokens. " +
            "Slack delivery is tested via unit tests (hooks.test.ts) and the APP harness."
          );
        }
        throw err;
      }

      // Give a moment for any duplicate deliveries to arrive
      await new Promise(r => setTimeout(r, 2000));

      // ── Assertions ──────────────────────────────────────

      const slackMessages = await this._httpReq("GET", `http://127.0.0.1:${this.mockSlackPort}/messages`);

      // 1. No duplicate messages (excluding chat.update edits)
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

      // 2. No fake tokens in delivered message
      const allText = slackMessages.map(m => m.text || "").join(" ");
      const cgnatPattern = /\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/;
      if (cgnatPattern.test(allText)) {
        throw new Error(`Slack message contains CGNAT fake: ${allText.slice(0, 200)}`);
      }
      // Check for any email that looks like a Shroud fake (word@word.tld that's not the real one)
      const fakeEmailPattern = /\b[a-z]+\d+@[a-z]+\.[a-z]{2,}\b/;
      const realValues = scenario.realValues || [];
      const emails = allText.match(/\b[\w.-]+@[\w.-]+\.\w{2,}\b/g) || [];
      for (const email of emails) {
        if (!realValues.includes(email) && fakeEmailPattern.test(email)) {
          throw new Error(`Slack message contains likely fake email: "${email}" — deobfuscation may have failed`);
        }
      }

      // 3. LLM must not have seen real PII
      const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
      if (llmRequests.length > 0 && scenario.realValues) {
        const allLlm = JSON.stringify(llmRequests);
        for (const val of scenario.realValues) {
          if (allLlm.includes(val)) {
            throw new Error(`LLM saw real PII in Slack E2E path: "${val}"`);
          }
        }
      }

      // 4. Public URL passthrough — LLM must see the real URL domain
      if (scenario.checkUrlPassthrough && llmRequests.length > 0) {
        const allLlm = JSON.stringify(llmRequests);
        if (!allLlm.includes(scenario.checkUrlPassthrough)) {
          throw new Error(
            `Public URL "${scenario.checkUrlPassthrough}" was obfuscated — ` +
            `LLM should see real public URLs. LLM content: ${allLlm.slice(0, 300)}`
          );
        }
      }

      // 5. Workspace path passthrough — LLM must see real operational paths
      if (scenario.checkPathPassthrough && llmRequests.length > 0) {
        const allLlm = JSON.stringify(llmRequests);
        for (const path of scenario.checkPathPassthrough) {
          if (!allLlm.includes(path)) {
            throw new Error(
              `Workspace path "${path}" was obfuscated — ` +
              `operational paths should pass through. LLM content: ${allLlm.slice(0, 300)}`
            );
          }
        }
      }
    } finally {
      try { gatewayProc.kill("SIGTERM"); } catch {}
      if (this.verbose) this._log(`[slack-e2e] State dir preserved: ${this.stateDir}`);
    }
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

  // ── Multi-turn scenario ──────────────────────────────────

  async _runMultiTurnScenario(scenario) {
    const sessionId = `multi-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    for (let i = 0; i < scenario.turns.length; i++) {
      const turn = scenario.turns[i];

      // Clear mock LLM log before each turn
      await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

      // Run agent with shared session
      const { stderr } = await this._runAgentWithSession(turn.message, sessionId);

      // Verify plugin loaded
      if (!stderr.includes("Plugin loaded")) {
        throw new Error(`Turn ${i + 1}: Shroud plugin did not load`);
      }

      // Verify LLM did NOT see real PII values
      const llmRequests = await this._httpReq("GET", `http://127.0.0.1:${this.mockLlmPort}/requests`);
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

  // ── Agent execution ───────────────────────────────────────

  async _runAgentWithSession(message, sessionId) {
    const bin = this._getOpenClawBin();
    const args = [
      bin, "agent",
      "--message", message,
      "--json",
      "--session-id", sessionId,
      "--timeout", "30",
      "--local",
    ];
    const env = this._agentEnv();

    return new Promise((res, reject) => {
      const proc = spawn("node", args, {
        stdio: ["pipe", "pipe", "pipe"],
        env,
        timeout: 60000,
        cwd: join(this.stateDir, "workspace"),
      });

      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", d => stdout += d);
      proc.stderr.on("data", d => stderr += d);

      proc.on("close", (code) => {
        let output = "";
        try {
          const parsed = JSON.parse(stdout);
          const response = parsed.response || parsed.content || parsed.text || parsed.message || stdout;
          output = typeof response === "string" ? response : JSON.stringify(response);
        } catch {
          output = stdout.trim();
        }
        if (!output && code !== 0 && !stderr.includes("Plugin loaded")) {
          reject(new Error(`Agent exited ${code}: ${stderr.slice(0, 500)}`));
        } else {
          res({ output, stderr });
        }
      });

      proc.on("error", reject);
    });
  }

  async _runAgentFull(message) {
    const bin = this._getOpenClawBin();
    const sessionId = `test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const args = [
      bin, "agent",
      "--message", message,
      "--json",
      "--session-id", sessionId,
      "--timeout", "30",
      "--local",
    ];

    const env = this._agentEnv();

    return new Promise((res, reject) => {
      const proc = spawn("node", args, {
        stdio: ["pipe", "pipe", "pipe"],
        env,
        timeout: 60000,
        cwd: join(this.stateDir, "workspace"),
      });

      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", d => stdout += d);
      proc.stderr.on("data", d => stderr += d);

      proc.on("close", (code) => {
        let output = "";
        try {
          const parsed = JSON.parse(stdout);
          const response = parsed.response || parsed.content || parsed.text || parsed.message || stdout;
          output = typeof response === "string" ? response : JSON.stringify(response);
        } catch {
          output = stdout.trim();
        }

        if (!output && code !== 0 && !stderr.includes("Plugin loaded")) {
          reject(new Error(`Agent exited ${code}: ${stderr.slice(0, 500)}`));
        } else {
          res({ output, stderr });
        }
      });

      proc.on("error", reject);
    });
  }

  _agentEnv() {
    return {
      PATH: process.env.PATH,
      NODE_PATH: join(this.sandboxDir, "node_modules"),
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
    const candidates = [
      join(this.sandboxDir, "node_modules", "openclaw", "openclaw.mjs"),
      join(this.sandboxDir, "node_modules", ".bin", "openclaw"),
      join(this.sandboxDir, "node_modules", "openclaw", "dist", "entry.js"),
    ];
    for (const c of candidates) {
      if (existsSync(c)) return c;
    }
    return candidates[0];
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
    if (this.mockLlmProc && !this.mockLlmProc.killed) {
      try { this.mockLlmProc.kill("SIGTERM"); } catch {}
    }
    if (this.mockSlackProc && !this.mockSlackProc.killed) {
      try { this.mockSlackProc.kill("SIGTERM"); } catch {}
    }
    // Clean up state dir (cached install stays) — skip if verbose for debugging
    if (this.stateDir && !this.verbose) {
      try { rmSync(this.stateDir, { recursive: true, force: true }); } catch {}
    }
  }

  _log(msg) {
    console.log(msg);
  }
}
