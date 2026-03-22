#!/usr/bin/env node
/**
 * Shroud Stats CLI — show active rules, hit counts, store size.
 *
 * Usage:
 *   node scripts/shroud-stats.mjs                    # fresh instance, shows rulebase
 *   node scripts/shroud-stats.mjs --test "some text"  # obfuscate text then show hits
 *
 * Loads the shroud dist from ../dist/ relative to this script.
 */

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { readFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(__dirname, "..", "dist");

const { resolveConfig } = await import(resolve(distDir, "config.js"));
const { Obfuscator } = await import(resolve(distDir, "obfuscator.js"));
const { BUILTIN_PATTERNS } = await import(resolve(distDir, "detectors", "regex.js"));

// Load config from OpenClaw config file if available
let pluginConfig = {};
const configPaths = [
  resolve(process.env.HOME || "~", ".openclaw", "openclaw.json"),
];
for (const p of configPaths) {
  try {
    const raw = JSON.parse(readFileSync(p, "utf-8"));
    const entry = raw?.plugins?.entries?.["openclaw-shroud"];
    if (entry?.config) {
      pluginConfig = entry.config;
      break;
    }
  } catch {
    // skip
  }
}

const config = resolveConfig(pluginConfig);
const obf = new Obfuscator(config);

// If --test flag, obfuscate the provided text to generate hits
const testIdx = process.argv.indexOf("--test");
if (testIdx !== -1) {
  const text = process.argv.slice(testIdx + 1).join(" ");
  if (text) {
    obf.obfuscate(text);
    console.log(`\nObfuscated test input (${text.length} chars)\n`);
  }
}

// Gather stats
const overrides = config.detectorOverrides;
const { ruleHits, storeMappings } = obf.getStats();

// Build rule table
const rules = BUILTIN_PATTERNS.map((p) => {
  const ov = overrides[p.name];
  const enabled = ov?.enabled !== false;
  const confidence = ov?.confidence ?? p.confidence;
  const hits = ruleHits[`regex:${p.name}`] ?? 0;
  return { name: p.name, category: p.category, enabled, confidence, hits };
});

rules.sort((a, b) => b.hits - a.hits);

// Format table
const maxName = Math.max(...rules.map((r) => r.name.length), 4);
const maxCat = Math.max(...rules.map((r) => r.category.length), 8);

const header = `${"Rule".padEnd(maxName)}  ${"Category".padEnd(maxCat)}  Status    Conf   Hits`;
const sep = "─".repeat(header.length + 20);

console.log(`Shroud Rule Hits`);
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
