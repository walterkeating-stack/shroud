/**
 * Reporter — console and JSON output for test results.
 */

import fs from "node:fs";

const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

export class Reporter {
  /**
   * Print a colored summary to the console.
   * @param {object} results — { scenarios, passed, failed, skipped, errors, duration }
   * @param {boolean} verbose — show individual test details
   */
  static console(results, verbose = false) {
    const { scenarios, passed, failed, skipped, duration } = results;

    console.log();
    console.log(`${BOLD}Shroud Integration Test Results${RESET}`);
    console.log(`${"=".repeat(50)}`);
    console.log();

    for (const scenario of scenarios) {
      const icon = scenario.failures > 0 ? `${RED}\u2718${RESET}` : `${GREEN}\u2714${RESET}`;
      const counts = `${GREEN}${scenario.passed} passed${RESET}`;
      const failCounts = scenario.failures > 0 ? ` ${RED}${scenario.failures} failed${RESET}` : "";
      console.log(`${icon} ${BOLD}${scenario.name}${RESET}  ${counts}${failCounts}  ${DIM}(${scenario.duration}ms)${RESET}`);

      if (verbose || scenario.failures > 0) {
        for (const test of scenario.tests) {
          if (test.status === "pass") {
            if (verbose) {
              console.log(`    ${GREEN}\u2714${RESET} ${test.name}  ${DIM}(${test.duration}ms)${RESET}`);
            }
          } else if (test.status === "fail") {
            console.log(`    ${RED}\u2718${RESET} ${test.name}`);
            console.log(`      ${RED}${test.error}${RESET}`);
          } else if (test.status === "skip") {
            console.log(`    ${YELLOW}-${RESET} ${test.name} ${DIM}(skipped)${RESET}`);
          }
        }
      }
    }

    console.log();
    console.log(`${"=".repeat(50)}`);

    const summary = [];
    summary.push(`${GREEN}${passed} passed${RESET}`);
    if (failed > 0) summary.push(`${RED}${failed} failed${RESET}`);
    if (skipped > 0) summary.push(`${YELLOW}${skipped} skipped${RESET}`);
    summary.push(`${DIM}${duration}ms${RESET}`);

    console.log(`${BOLD}Total:${RESET} ${summary.join("  ")}`);
    console.log();
  }

  /**
   * Write a JSON report to disk.
   * @param {object} results
   * @param {string} filePath
   */
  static json(results, filePath) {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        total: results.passed + results.failed + results.skipped,
        passed: results.passed,
        failed: results.failed,
        skipped: results.skipped,
        duration_ms: results.duration,
      },
      scenarios: results.scenarios.map((s) => ({
        name: s.name,
        file: s.file,
        passed: s.passed,
        failures: s.failures,
        duration_ms: s.duration,
        tests: s.tests.map((t) => ({
          name: t.name,
          status: t.status,
          duration_ms: t.duration,
          error: t.error || null,
          obfuscation: t.obfuscation || null,
          deobfuscation: t.deobfuscation || null,
        })),
      })),
    };

    fs.writeFileSync(filePath, JSON.stringify(report, null, 2) + "\n");
    console.log(`${DIM}Report written to ${filePath}${RESET}`);
  }
}
