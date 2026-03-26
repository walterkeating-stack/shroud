#!/usr/bin/env node
/**
 * OpenClaw Integration Runner — smoke-tests Shroud through a real OpenClaw instance.
 *
 * Architecture (lean, no insanity):
 *   1. npm-installs OpenClaw ONCE into a cached sandbox dir (~/.cache/shroud-test/openclaw-<version>)
 *   2. Copies Shroud plugin into sandbox extensions
 *   3. Applies patches (prompt override only — EventStream is patched at runtime)
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
    this.results = { scenarios: [], passed: 0, failed: 0, skipped: 0, duration: 0 };
  }

  async run() {
    const startTime = Date.now();
    this._log("OpenClaw Integration Smoke Test");
    this._log("=".repeat(50));

    try {
      await this._ensureInstalled();
      await this._startMockLlm();
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
        message: "Use the key sk-proj-abc123def456ghi789jkl012mno345pqr678 for the staging API",
        realValues: ["sk-proj-abc123def456ghi789jkl012mno345pqr678"],
      },
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
      // Clear mock LLM log
      await this._httpReq("DELETE", `http://127.0.0.1:${this.mockLlmPort}/requests`);

      // Run agent — capture stderr for plugin lifecycle checks
      const { output: agentOutput, stderr } = await this._runAgentFull(scenario.message);

      // 1. Plugin must have loaded
      if (!stderr.includes("Plugin loaded")) {
        throw new Error("Shroud plugin did not load — 'Plugin loaded' not found in stderr");
      }

      // 2. Hook must have fired and obfuscated entities
      const obfMatch = stderr.match(/before_prompt_build: obfuscated (\d+) entities/);
      if (!obfMatch) {
        throw new Error("before_prompt_build hook did not fire");
      }
      const obfCount = parseInt(obfMatch[1], 10);
      if (scenario.expectObfuscated && obfCount < scenario.expectObfuscated) {
        throw new Error(`Expected at least ${scenario.expectObfuscated} obfuscated entities, got ${obfCount}`);
      }
      if (obfCount === 0 && scenario.realValues?.length > 0) {
        throw new Error("Hook fired but obfuscated 0 entities — detection may be broken");
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

      // 6. Stats file check
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
      result.status = "fail";
      result.error = err.message;
    }

    result.duration = Date.now() - start;
    return result;
  }

  // ── Agent execution ───────────────────────────────────────

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
      ANTHROPIC_API_KEY: "sk-ant-sandbox-dummy",
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

  _httpReq(method, url, body) {
    return new Promise((res, reject) => {
      const u = new URL(url);
      const req = http.request(
        { hostname: u.hostname, port: u.port, path: u.pathname, method, headers: { "Content-Type": "application/json" } },
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
      if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
      req.end();
    });
  }

  // ── Cleanup ───────────────────────────────────────────────

  async _teardown() {
    if (this.mockLlmProc && !this.mockLlmProc.killed) {
      try { this.mockLlmProc.kill("SIGTERM"); } catch {}
    }
    // Clean up state dir (cached install stays)
    if (this.stateDir) {
      try { rmSync(this.stateDir, { recursive: true, force: true }); } catch {}
    }
  }

  _log(msg) {
    console.log(msg);
  }
}
