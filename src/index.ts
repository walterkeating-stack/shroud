/**
 * Shroud -- OpenClaw privacy plugin.
 *
 * Automatically obfuscates sensitive data before it reaches the LLM
 * and deobfuscates responses before they reach the user.
 */

import { existsSync, readFileSync, writeFileSync, copyFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { resolveConfig } from "./config.js";
import { Obfuscator } from "./obfuscator.js";
import { registerHooks } from "./hooks.js";

// ---------------------------------------------------------------------------
// Runtime self-patch: ensure pi-ai's EventStream.push() has the
// Shroud deobfuscation hook. Runs once on first load; subsequent loads
// detect the patch and skip. If patching occurs, the user is told to restart.
// ---------------------------------------------------------------------------
const PATCH_MARKER = "__shroudStreamDeobfuscate";
const PATCH_CODE = [
  "        // Shroud deobfuscation hook (injected by shroud-privacy plugin)",
  "        const deob = globalThis.__shroudStreamDeobfuscate;",
  "        if (deob && event && typeof event === 'object') {",
  "            event = deob(this, event);",
  "        }",
].join("\n");

function findEventStreamPath(logger: any): string | null {
  try {
    const esmRequire = createRequire(import.meta.url);
    const cache = esmRequire.cache;
    if (!cache) return null;

    // Find OpenClaw's install root from require.cache
    for (const key of Object.keys(cache)) {
      const idx = key.indexOf("/openclaw/");
      if (idx === -1) continue;
      const root = key.slice(0, idx + "/openclaw/".length);
      const candidate = join(root, "node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js");
      if (existsSync(candidate)) return candidate;
    }
  } catch {}

  return null;
}

function ensureEventStreamPatched(logger: any): void {
  const esPath = findEventStreamPath(logger);
  if (!esPath) {
    logger?.info("[shroud] Could not locate pi-ai event-stream.js — streaming deobfuscation unavailable");
    return;
  }

  try {
    const content = readFileSync(esPath, "utf8");

    // Already patched
    if (content.includes(PATCH_MARKER)) return;

    // Back up original
    const backupPath = esPath + ".shroud-backup";
    if (!existsSync(backupPath)) {
      copyFileSync(esPath, backupPath);
    }

    // Patch: insert hook after "push(event) {"
    const target = "    push(event) {";
    if (!content.includes(target)) {
      logger?.warn("[shroud] Could not find push(event) in event-stream.js — patch skipped");
      return;
    }

    const patched = content.replace(target, target + "\n" + PATCH_CODE);
    writeFileSync(esPath, patched);

    // Clear Node.js V8 compile cache
    const cacheDir = process.env.NODE_COMPILE_CACHE || "/tmp/node-compile-cache";
    if (existsSync(cacheDir)) {
      try {
        const uid = process.getuid?.() ?? "";
        for (const entry of readdirSync(cacheDir)) {
          const full = join(cacheDir, entry);
          if (uid && entry.endsWith(`-${uid}`)) {
            rmSync(full, { recursive: true, force: true });
          }
        }
      } catch {}
    }

    logger?.warn(
      "[shroud] Patched pi-ai EventStream for streaming deobfuscation. Restarting gateway...",
    );

    // Auto-restart: send SIGUSR1 to self after a short delay.
    // OpenClaw handles SIGUSR1 as a graceful restart signal.
    setTimeout(() => {
      try {
        process.kill(process.pid, "SIGUSR1");
      } catch {
        logger?.warn("[shroud] Auto-restart failed. Run: openclaw gateway restart");
      }
    }, 3000);
  } catch (err) {
    logger?.warn(`[shroud] Failed to patch event-stream.js: ${String(err)}`);
  }
}

export default {
  id: "shroud-privacy",
  name: "Shroud",
  register(api: any) {
    // Ensure pi-ai is patched for streaming deobfuscation
    ensureEventStreamPatched(api.logger);

    const config = resolveConfig(api.pluginConfig);
    let obfuscator = new Obfuscator(config);

    registerHooks(api, obfuscator);

    // After registerHooks, the shared global obfuscator may have replaced ours.
    // All tools must use the same instance that the hooks use.
    const g = globalThis as any;
    if (g.__shroudObfuscator) {
      obfuscator = g.__shroudObfuscator;
    }

    // Register shroud_status tool
    api.registerTool({
      name: "shroud_status",
      description:
        "Show Shroud privacy stats: entity counts, session info, audit status",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      handler: async () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify(obfuscator.getStats(), null, 2),
          },
        ],
      }),
    });

    // Register shroud_reset tool
    api.registerTool({
      name: "shroud_reset",
      description:
        "Clear all Shroud mappings and start a fresh privacy session",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      handler: async () => {
        obfuscator.reset();
        return {
          content: [
            {
              type: "text",
              text: "Shroud session reset. All mappings cleared.",
            },
          ],
        };
      },
    });

    api.logger?.info(
      "[shroud] Plugin loaded — native TypeScript, no proxy required.",
    );
  },
};
