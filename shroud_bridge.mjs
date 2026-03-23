#!/usr/bin/env node
/**
 * Shroud Bridge — JSON-RPC server over stdin/stdout.
 *
 * Loads the shroud Obfuscator from a configurable dist path and exposes
 * obfuscate / deobfuscate / reset / getStats / configure via newline-
 * delimited JSON messages.
 *
 * Protocol:
 *   → {"id":1,"method":"obfuscate","params":{"text":"..."}}
 *   ← {"id":1,"result":{"obfuscated":"...","entityCount":3,"audit":{...}}}
 *
 *   → {"id":2,"method":"deobfuscate","params":{"text":"..."}}
 *   ← {"id":2,"result":{"text":"...","replacementCount":2,"audit":{...}}}
 *
 *   → {"id":3,"method":"reset"}
 *   ← {"id":3,"result":{"ok":true}}
 *
 *   → {"id":4,"method":"getStats"}
 *   ← {"id":4,"result":{...}}
 *
 *   → {"id":5,"method":"ping"}
 *   ← {"id":5,"result":{"ok":true,"version":"1.3.0"}}
 */

import { createHash, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { writeFileSync } from "node:fs";

// Shroud dist path passed as first CLI arg (default: ./dist relative to this script)
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = dirname(fileURLToPath(import.meta.url));
const shroudDist = process.argv[2] || resolve(__dirname, "dist");

// Dynamically import the Obfuscator and config resolver
const { Obfuscator } = await import(
  pathToFileURL(resolve(shroudDist, "obfuscator.js")).href
);
const { resolveConfig } = await import(
  pathToFileURL(resolve(shroudDist, "config.js")).href
);

// Read plugin config from env var (JSON) or use defaults
let pluginConfig = {};
if (process.env.SHROUD_PLUGIN_CONFIG) {
  try {
    pluginConfig = JSON.parse(process.env.SHROUD_PLUGIN_CONFIG);
  } catch (e) {
    process.stderr.write(`[shroud-bridge] Bad SHROUD_PLUGIN_CONFIG: ${e.message}\n`);
  }
}

const config = resolveConfig(pluginConfig);
let obfuscator = new Obfuscator(config);

// Hash chain: each audit entry includes hash of previous entry for tamper evidence
let chainHash = "0000000000000000";

function advanceChain(data) {
  const payload = chainHash + JSON.stringify(data);
  chainHash = createHash("sha256").update(payload).digest("hex").slice(0, 16);
  return chainHash;
}

function proofHash(text) {
  const salt = config.auditHashSalt || "";
  const truncate = config.auditHashTruncate || 12;
  return createHash("sha256")
    .update(salt + text)
    .digest("hex")
    .slice(0, truncate);
}

const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";

function dumpStats() {
  try {
    const stats = obfuscator.getStats();
    stats.updatedAt = new Date().toISOString();
    stats.pid = process.pid;
    writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2) + "\n");
  } catch {
    // best-effort
  }
}

process.stderr.write("[shroud-bridge] Ready.\n");

// Signal readiness to parent process
process.stdout.write(JSON.stringify({ ready: true, version: "1.3.0" }) + "\n");

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch (e) {
    process.stdout.write(
      JSON.stringify({ id: null, error: `Parse error: ${e.message}` }) + "\n"
    );
    return;
  }

  const { id, method, params } = req;
  let result;
  try {
    switch (method) {
      case "ping":
        result = { ok: true, version: "1.3.0" };
        break;

      case "obfuscate": {
        const text = params?.text ?? "";
        const out = obfuscator.obfuscate(text);
        const categories = {};
        for (const e of out.entities) {
          categories[e.category] = (categories[e.category] || 0) + 1;
        }
        result = {
          obfuscated: out.obfuscated,
          entityCount: out.entities.length,
          categories,
        };

        // Always include audit data in response — Python side decides what to log
        if (config.auditEnabled || config.verboseLogging) {
          const reqId = randomBytes(8).toString("hex");
          const audit = {
            req: reqId,
            totalEntities: out.entities.length,
            inputChars: text.length,
            outputChars: out.obfuscated.length,
            charDelta: out.obfuscated.length - text.length,
            byCategory: categories,
            modified: out.obfuscated !== text,
            proofIn: proofHash(text),
            proofOut: proofHash(out.obfuscated),
          };

          // Fake samples (only fake values, never real)
          const maxFakes = config.auditMaxFakesSample || 3;
          audit.fakesSample = Object.values(out.mappingsUsed).slice(0, maxFakes);

          // Advance tamper-evident hash chain
          audit.chainHash = advanceChain(audit);

          result.audit = audit;
        }
        dumpStats();
        break;
      }

      case "deobfuscate": {
        const text = params?.text ?? "";
        const deobResult = obfuscator.deobfuscateWithStats
          ? obfuscator.deobfuscateWithStats(text)
          : { text: obfuscator.deobfuscate(text), replacementCount: 0 };

        // Always include store size for diagnostics
        const stats = obfuscator.getStats();
        result = {
          text: deobResult.text,
          replacementCount: deobResult.replacementCount,
          storeSize: stats.storeMappings ?? 0,
        };

        if (config.auditEnabled || config.verboseLogging) {
          const audit = {
            replacementCount: deobResult.replacementCount,
            storeSize: stats.storeMappings ?? 0,
            inputChars: text.length,
            outputChars: deobResult.text.length,
            modified: deobResult.text !== text,
            proofIn: proofHash(text),
            proofOut: proofHash(deobResult.text),
          };
          // Correlate with request via chain
          audit.chainHash = advanceChain(audit);
          result.audit = audit;
        }
        dumpStats();
        break;
      }

      case "reset":
        obfuscator.reset();
        chainHash = "0000000000000000";
        dumpStats();
        result = { ok: true };
        break;

      case "getStats":
        result = obfuscator.getStats();
        result.chainHash = chainHash;
        break;

      case "reconfigure": {
        // Hot-reload config without restarting the process
        const newConfig = resolveConfig(params?.config ?? {});
        obfuscator = new Obfuscator(newConfig);
        result = { ok: true, config: newConfig };
        break;
      }

      default:
        result = undefined;
        process.stdout.write(
          JSON.stringify({ id, error: `Unknown method: ${method}` }) + "\n"
        );
        return;
    }
    process.stdout.write(JSON.stringify({ id, result }) + "\n");
  } catch (e) {
    process.stdout.write(
      JSON.stringify({ id, error: `${method} failed: ${e.message}` }) + "\n"
    );
  }
});

rl.on("close", () => process.exit(0));
