#!/usr/bin/env node
/**
 * Shroud Test Harness — CLI entry point.
 *
 * Usage:
 *   node run.mjs                          # Run all APP scenarios (359 tests)
 *   node run.mjs --openclaw               # OpenClaw E2E tests (Docker only — use compat/run-compat.sh)
 *   node run.mjs --scenario basic-pii     # Filter by scenario name
 *   node run.mjs --verbose                # Detailed output
 *   node run.mjs --report reports/r.json  # Save JSON report
 *   node run.mjs --shroud-path ../shroud  # Custom shroud path
 */

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
const lifecycle = args.includes("--lifecycle");

// OpenClaw E2E tests — runs inside Docker container only
if (useOpenClaw) {
  const { OpenClawRunner } = await import("./harness/openclaw-runner.mjs");
  const runner = new OpenClawRunner({
    shroudPath,
    verbose,
    scenario: getArg("--scenario"),
    lifecycle,
  });
  const results = await runner.run();

  if (reportPath) {
    Reporter.json(results, reportPath);
  }

  process.exit(results.failed > 0 ? 1 : 0);
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
