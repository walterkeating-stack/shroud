#!/usr/bin/env node
/**
 * Shroud Test Runner — unified integration test runner.
 *
 * Orchestrates: mock LLM + APP engine + all scenario JSON files.
 * No OpenClaw, no sandboxes, no network namespaces. Just Shroud.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { APPClient } from "../lib/app-client.mjs";
import {
  assertLlmDidNotSee,
  assertLlmSawPattern,
  assertUserSees,
  assertEntityCount,
  assertCategories,
  assertNoCgnatLeak,
  assertNoCgnatRangeLeak,
  assertNoUlaLeak,
  assertRoundtrip,
} from "../lib/assertions.mjs";
import { Reporter } from "./reporter.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Simple HTTP JSON request. */
function httpRequest(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers: { "Content-Type": "application/json", Authorization: "Bearer test-key" },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          try { resolve(JSON.parse(raw)); } catch { resolve(raw); }
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

export class Runner {
  #opts;
  #mockLlmProc = null;
  #mockLlmPort = null;
  #appClient = null;

  constructor(opts = {}) {
    this.#opts = {
      scenario: opts.scenario || null,
      verbose: opts.verbose || false,
      reportPath: opts.reportPath || null,
      shroudPath: opts.shroudPath || "../shroud",
    };
  }

  async run() {
    const startTime = Date.now();

    try {
      await this.#startMockLlm();
      if (this.#opts.verbose) console.log(`Mock LLM on port ${this.#mockLlmPort}`);

      await this.#startApp();
      await this.#appClient.identify({ agent: "shroud-test-harness", version: "1.0.0", channel: "test" });
      if (this.#opts.verbose) console.log("APP engine connected");

      const scenarioFiles = this.#loadScenarioFiles();
      if (this.#opts.verbose) console.log(`Loaded ${scenarioFiles.length} scenario file(s)`);

      const scenarioResults = [];
      let totalPassed = 0;
      let totalFailed = 0;
      let totalSkipped = 0;

      for (const sf of scenarioFiles) {
        // Fresh secret key per scenario file to avoid HMAC collisions across files.
        if (this.#appClient) {
          try { await this.#appClient.shutdown(); } catch {}
        }
        await this.#startApp();
        await this.#appClient.identify({ agent: "shroud-test-harness", version: "1.0.0", channel: "test" });

        const result = await this.#runScenario(sf);
        scenarioResults.push(result);
        totalPassed += result.passed;
        totalFailed += result.failures;
        totalSkipped += result.tests.filter((t) => t.status === "skip").length;
      }

      const results = {
        scenarios: scenarioResults,
        passed: totalPassed,
        failed: totalFailed,
        skipped: totalSkipped,
        duration: Date.now() - startTime,
      };

      Reporter.console(results, this.#opts.verbose);
      if (this.#opts.reportPath) Reporter.json(results, this.#opts.reportPath);

      return results;
    } finally {
      await this.#cleanup();
    }
  }

  // ── Mock LLM ──────────────────────────────────────────────

  async #startMockLlm() {
    const serverPath = path.resolve(__dirname, "..", "mock-llm", "server.mjs");

    return new Promise((resolve, reject) => {
      this.#mockLlmProc = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PORT: "0" },
      });

      const timeout = setTimeout(() => reject(new Error("Mock LLM failed to start within 5s")), 5000);
      const rl = createInterface({ input: this.#mockLlmProc.stdout });

      rl.once("line", (line) => {
        try {
          const info = JSON.parse(line);
          if (info.ready && info.port) {
            this.#mockLlmPort = info.port;
            clearTimeout(timeout);
            resolve();
          }
        } catch (err) {
          clearTimeout(timeout);
          reject(new Error(`Failed to parse mock LLM startup: ${line}`));
        }
      });

      this.#mockLlmProc.on("error", (err) => { clearTimeout(timeout); reject(err); });
    });
  }

  // ── APP Engine ────────────────────────────────────────────

  async #startApp() {
    const shroudDist = path.resolve(this.#opts.shroudPath);
    const serverPath = path.join(shroudDist, "app-server.mjs");

    if (!fs.existsSync(serverPath)) {
      throw new Error(
        `Shroud app-server not found at ${serverPath}. ` +
        `Build shroud first (cd ${shroudDist} && npm run build) or pass --shroud-path.`,
      );
    }

    // Isolate test APP server from live session/event files
    process.env.SHROUD_APP_SESSIONS_FILE = "/tmp/shroud-test-app-sessions.json";
    process.env.SHROUD_APP_EVENTS_FILE = "/tmp/shroud-test-app-events.jsonl";
    this.#appClient = await APPClient.spawn("node", [serverPath]);
  }

  // ── Scenario Loading ──────────────────────────────────────

  #loadScenarioFiles() {
    const scenarioDir = path.resolve(__dirname, "scenarios");
    // Skip docker-* scenario files — those run only in Docker E2E via openclaw-runner
    let files = fs.readdirSync(scenarioDir).filter((f) => f.endsWith(".json") && !f.startsWith("docker-"));

    if (this.#opts.scenario) {
      const filter = this.#opts.scenario;
      files = files.filter(
        (f) => f === filter || f === `${filter}.json` || f.includes(filter),
      );
      if (files.length === 0) {
        throw new Error(`No scenario files matching "${filter}" in ${scenarioDir}`);
      }
    }

    return files.map((f) => {
      const raw = JSON.parse(fs.readFileSync(path.join(scenarioDir, f), "utf-8"));
      const tests = Array.isArray(raw) ? raw : (raw.tests || []);
      const name = raw.name || f.replace(/\.json$/, "");
      return { file: f, name, tests };
    });
  }

  // ── Scenario Execution ────────────────────────────────────

  async #runScenario(scenarioFile) {
    const { file, name, tests } = scenarioFile;
    const scenarioStart = Date.now();
    const testResults = [];
    let passed = 0;
    let failures = 0;

    for (const test of tests) {
      await this.#appClient.reset();
      const result = await this.#runTest(test);
      testResults.push(result);
      if (result.status === "pass") passed++;
      else if (result.status === "fail") failures++;
    }

    return { file, name, passed, failures, duration: Date.now() - scenarioStart, tests: testResults };
  }

  async #runTest(test) {
    const testStart = Date.now();
    const result = { name: test.name, status: "pass", duration: 0 };

    try {
      const a = test.assertions || {};
      const llmBase = `http://127.0.0.1:${this.#mockLlmPort}`;

      // Clear mock LLM request log
      await httpRequest("DELETE", `${llmBase}/requests`);

      // Obfuscate
      const obfResult = await this.#appClient.obfuscate(test.input);
      result.obfuscation = {
        entityCount: obfResult.entityCount,
        categories: obfResult.categories,
        modified: obfResult.modified,
      };

      // Send obfuscated text to mock LLM
      await httpRequest("POST", `${llmBase}/v1/chat/completions`, {
        model: "mock-model",
        stream: false,
        messages: [{ role: "user", content: obfResult.text }],
      });

      // Fetch what LLM received
      const requestLog = await httpRequest("GET", `${llmBase}/requests`);

      // LLM-side assertions
      if (a.llm_must_not_see) assertLlmDidNotSee(requestLog, a.llm_must_not_see);
      if (a.llm_must_see_pattern) assertLlmSawPattern(requestLog, a.llm_must_see_pattern);

      // Deobfuscate the obfuscated text (direct roundtrip — no LLM echo dependency)
      const deobResult = await this.#appClient.deobfuscate(obfResult.text);
      result.deobfuscation = {
        replacementCount: deobResult.replacementCount,
        modified: deobResult.modified,
      };

      // User-side assertions
      if (a.user_must_see) assertUserSees(deobResult.text, a.user_must_see);
      if (a.no_cgnat_leak === true) assertNoCgnatLeak(deobResult.text);
      if (a.no_cgnat_range_leak) assertNoCgnatRangeLeak(deobResult.text);
      if (a.no_ula_leak) assertNoUlaLeak(deobResult.text);

      if (a.entity_count_min !== undefined || a.entity_count_max !== undefined) {
        assertEntityCount(obfResult, a.entity_count_min, a.entity_count_max);
      }
      if (a.categories) assertCategories(obfResult, a.categories);

      if (a.roundtrip) assertRoundtrip(obfResult.text, deobResult.text, test.input);

      // E.164 check on fake phone surrogates (relevant for WhatsApp delivery)
      if (a.fake_phones_must_be_e164) {
        const phonePattern = /\+\d{7,15}/g;
        const fakePhones = obfResult.text.match(phonePattern) || [];
        for (const fp of fakePhones) {
          if (!/^\+[1-9]\d{6,14}$/.test(fp)) {
            throw new Error(`Fake phone "${fp}" is not valid E.164`);
          }
        }
      }
    } catch (err) {
      result.status = "fail";
      result.error = err.message;
    }

    result.duration = Date.now() - testStart;
    return result;
  }

  // ── Cleanup ───────────────────────────────────────────────

  async #cleanup() {
    try { if (this.#appClient) await this.#appClient.shutdown(); } catch {}
    if (this.#mockLlmProc && !this.#mockLlmProc.killed) this.#mockLlmProc.kill("SIGTERM");
  }
}
