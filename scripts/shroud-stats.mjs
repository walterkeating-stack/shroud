#!/usr/bin/env node
/**
 * Shroud Stats CLI — show active rules, hit counts, store size.
 *
 * Usage:
 *   node scripts/shroud-stats.mjs                    # live stats from running gateway
 *   node scripts/shroud-stats.mjs --test "some text"  # obfuscate text then show hits
 *
 * Reads live stats from /tmp/shroud-stats.json (written by shroud_bridge.mjs).
 * Falls back to a fresh instance if no stats file exists.
 */

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { readFileSync, existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(__dirname, "..", "dist");

const { resolveConfig } = await import(resolve(distDir, "config.js"));
const { Obfuscator } = await import(resolve(distDir, "obfuscator.js"));
const { BUILTIN_PATTERNS } = await import(resolve(distDir, "detectors", "regex.js"));

// Load config from OpenClaw config file if available
let pluginConfig = {};
try {
  const configPath = resolve(process.env.HOME || "~", ".openclaw", "openclaw.json");
  const raw = JSON.parse(readFileSync(configPath, "utf-8"));
  const entry = raw?.plugins?.entries?.["shroud-privacy"];
  if (entry?.config) pluginConfig = entry.config;
} catch {
  // skip
}

const config = resolveConfig(pluginConfig);
const overrides = config.detectorOverrides;

// Try to read live stats from the bridge stats file
const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";
let liveStats = null;
let source = "fresh instance";

if (existsSync(STATS_FILE) && !process.argv.includes("--test")) {
  try {
    liveStats = JSON.parse(readFileSync(STATS_FILE, "utf-8"));
    source = `live (pid ${liveStats.pid}, updated ${liveStats.updatedAt})`;
  } catch {
    // fall through to fresh instance
  }
}

// If --test flag or no live stats, use a fresh obfuscator
let ruleHits;
let storeMappings;

if (liveStats && !process.argv.includes("--test")) {
  ruleHits = liveStats.ruleHits || {};
  storeMappings = liveStats.storeMappings || 0;
} else {
  const obf = new Obfuscator(config);
  const testIdx = process.argv.indexOf("--test");
  if (testIdx !== -1) {
    const text = process.argv.slice(testIdx + 1).join(" ");
    if (text) {
      obf.obfuscate(text);
      source = `test input (${text.length} chars)`;
    }
  }
  const stats = obf.getStats();
  ruleHits = stats.ruleHits;
  storeMappings = stats.storeMappings;
}

// Build rule table
const rules = BUILTIN_PATTERNS.map((p) => {
  const ov = overrides[p.name];
  const enabled = ov?.enabled !== false;
  const confidence = ov?.confidence ?? p.confidence;
  const hits = ruleHits[`regex:${p.name}`] ?? 0;
  return { name: p.name, category: p.category, enabled, confidence, hits };
});

rules.sort((a, b) => b.hits - a.hits);

// JSON output mode
if (process.argv.includes("--json")) {
  const output = {
    source,
    storeMappings,
    auditEnabled: config.auditEnabled || config.verboseLogging || false,
    overrideCount: Object.keys(overrides).length,
    rules,
  };
  if (liveStats) {
    output.pid = liveStats.pid;
    output.updatedAt = liveStats.updatedAt;
  }
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
  process.exit(0);
}

// Format table
const maxName = Math.max(...rules.map((r) => r.name.length), 4);
const maxCat = Math.max(...rules.map((r) => r.category.length), 8);

const header = `${"Rule".padEnd(maxName)}  ${"Category".padEnd(maxCat)}  Status    Conf   Hits`;
const sep = "─".repeat(header.length + 20);

console.log(`Shroud Rule Hits (${source})`);
console.log(sep);
console.log(header);
console.log(sep);

for (const r of rules) {
  const status = r.enabled ? "active" : "DISABLED";
  const bar = r.hits > 0 ? " " + "█".repeat(Math.min(Math.ceil(Math.log2(r.hits + 1)), 16)) : "";
  console.log(
    `${r.name.padEnd(maxName)}  ${r.category.padEnd(maxCat)}  ${status.padEnd(8)}  ${r.confidence.toFixed(2).padStart(4)}  ${String(r.hits).padStart(5)}${bar}`
  );
}

console.log(sep);
console.log(`Store: ${storeMappings} active mappings`);
console.log(`Audit: ${config.auditEnabled || config.verboseLogging ? "enabled" : "disabled"}`);
console.log(`Config: detectorOverrides has ${Object.keys(overrides).length} override(s)`);
