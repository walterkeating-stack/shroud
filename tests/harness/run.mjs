#!/usr/bin/env node
/**
 * Shroud Test Harness — CLI entry point.
 *
 * Usage:
 *   node run.mjs                          # Run all APP scenarios (359 tests)
 *   node run.mjs --openclaw               # OpenClaw plugin integration smoke test
 *   node run.mjs --scenario basic-pii     # Filter by scenario name
 *   node run.mjs --verbose                # Detailed output
 *   node run.mjs --report reports/r.json  # Save JSON report
 *   node run.mjs --shroud-path ../shroud  # Custom shroud path
 */

import { execSync } from "node:child_process";
import { Reporter } from "./harness/reporter.mjs";
import { resolve } from "node:path";

const args = process.argv.slice(2);

function getArg(flag) {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : null;
}

const verbose = args.includes("--verbose") || args.includes("-v");
const shroudPath = getArg("--shroud-path") || resolve(import.meta.dirname, "../..");
const reportPath = getArg("--report");
const useOpenClaw = args.includes("--openclaw");

// Check latest OpenClaw version and report it
if (useOpenClaw) {
  let latest = "unknown";
  let versions = [];
  try {
    latest = execSync("npm view openclaw version", { encoding: "utf-8", timeout: 15000 }).trim();
    const allJson = execSync("npm view openclaw versions --json", { encoding: "utf-8", timeout: 15000 });
    versions = JSON.parse(allJson).filter(v => !v.includes("beta") && !v.includes("alpha"));
  } catch {}

  // Determine which versions to test
  const explicitVersion = getArg("--openclaw-version");
  const testBackcompat = args.includes("--backcompat");
  let versionsToTest;

  if (explicitVersion) {
    versionsToTest = [explicitVersion];
  } else if (testBackcompat && versions.length >= 2) {
    // Test latest + previous stable release
    const prev = versions[versions.length - 2];
    versionsToTest = [prev, latest];
    console.log(`Backwards compatibility: testing ${prev} + ${latest}`);
  } else {
    versionsToTest = [latest];
  }

  console.log(`Latest OpenClaw on npm: ${latest}`);

  const { OpenClawRunner } = await import("./harness/openclaw-runner.mjs");
  let anyFailed = false;

  for (const ver of versionsToTest) {
    console.log(`\n${"=".repeat(50)}`);
    console.log(`Testing with OpenClaw ${ver}`);
    console.log("=".repeat(50));

    const runner = new OpenClawRunner({
      shroudPath,
      verbose,
      scenario: getArg("--scenario"),
      openclawVersion: ver,
    });
    const results = await runner.run();

    if (reportPath) {
      const versionedPath = versionsToTest.length > 1
        ? reportPath.replace(/\.json$/, `-${ver}.json`)
        : reportPath;
      Reporter.json(results, versionedPath);
    }

    if (results.failed > 0) anyFailed = true;
  }

  process.exit(anyFailed ? 1 : 0);
}

// Default: APP integration tests (all 359 scenarios)
const { Runner } = await import("./harness/runner.mjs");
const runner = new Runner({
  scenario: getArg("--scenario"),
  verbose,
  reportPath,
  shroudPath,
});

const results = await runner.run();

if (reportPath) {
  Reporter.json(results, reportPath);
  console.log(`\nReport saved to: ${reportPath}`);
}

process.exit(results.failed > 0 ? 1 : 0);
