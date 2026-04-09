/**
 * Shroud -- OpenClaw privacy plugin.
 *
 * Automatically obfuscates sensitive data before it reaches the LLM
 * and deobfuscates responses before they reach the user.
 */

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { resolveConfig } from "./config.js";
import { Obfuscator } from "./obfuscator.js";
import { registerHooks } from "./hooks.js";
import { ConfigManager } from "./config-manager.js";

// ---------------------------------------------------------------------------
// Runtime prototype patch: wrap EventStream.prototype.push() with the
// Shroud deobfuscation hook. No file reads, no file writes, no cache
// clearing, no restarts needed. Works across OpenClaw versions because
// it patches the live prototype at import time.
// ---------------------------------------------------------------------------
const PATCH_MARKER = "__shroudEventStreamPatched";

function patchEventStreamPrototype(logger: any): void {
  // Already patched by another plugin instance — skip
  if ((globalThis as any)[PATCH_MARKER]) return;

  let EventStream: any = null;

  // Strategy 1: direct ESM import via createRequire
  try {
    const esmRequire = createRequire(import.meta.url);
    const mod = esmRequire("@mariozechner/pi-ai/dist/utils/event-stream.js");
    EventStream = mod?.EventStream ?? mod?.default?.EventStream;
  } catch {
    // Not resolvable from Shroud's own location — try from OpenClaw
  }

  // Strategy 2: walk require.cache to find OpenClaw's install root
  if (!EventStream) {
    try {
      const esmRequire = createRequire(import.meta.url);
      const cache = esmRequire.cache;
      if (cache) {
        for (const key of Object.keys(cache)) {
          const idx = key.indexOf("/openclaw/");
          if (idx === -1) continue;
          const root = key.slice(0, idx + "/openclaw/".length);
          try {
            const req2 = createRequire(root + "package.json");
            const mod = req2("@mariozechner/pi-ai/dist/utils/event-stream.js");
            EventStream = mod?.EventStream ?? mod?.default?.EventStream;
            if (EventStream) break;
          } catch { /* try next */ }
        }
      }
    } catch { /* no cache access */ }
  }

  // Strategy 3: resolve from process.argv[1] (the OpenClaw binary)
  if (!EventStream && process.argv[1]) {
    try {
      const binRequire = createRequire(process.argv[1]);
      const mod = binRequire("@mariozechner/pi-ai/dist/utils/event-stream.js");
      EventStream = mod?.EventStream ?? mod?.default?.EventStream;
    } catch { /* not found from binary location */ }
  }

  // Strategy 4: find the file on disk via known paths (bypasses exports restriction)
  if (!EventStream) {
    const candidates = [
      // From OpenClaw's npm global install
      process.argv[1] && join(dirname(dirname(process.argv[1])), "lib", "node_modules", "openclaw", "node_modules", "@mariozechner", "pi-ai", "dist", "utils", "event-stream.js"),
      // From npm global prefix
      join(process.env.HOME || "/root", ".npm-global", "lib", "node_modules", "openclaw", "node_modules", "@mariozechner", "pi-ai", "dist", "utils", "event-stream.js"),
      // Common global locations
      "/usr/local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js",
      "/usr/lib/node_modules/openclaw/node_modules/@mariozechner/pi-ai/dist/utils/event-stream.js",
    ].filter(Boolean) as string[];

    for (const candidate of candidates) {
      if (!existsSync(candidate)) continue;
      try {
        // Use dynamic import to load the ESM module directly by file path
        const fileUrl = "file://" + candidate;
        // We can't use top-level await, so use createRequire with the file's own dir
        // to bypass the parent package.json exports
        const localRequire = createRequire(candidate);
        // Try requiring from the file's own directory (no exports restriction from parent)
        const mod = localRequire("./event-stream.js");
        EventStream = mod?.EventStream ?? mod?.default?.EventStream;
        if (EventStream) break;
      } catch { /* try next */ }
    }
  }

  if (!EventStream?.prototype?.push) return;

  // Wrap prototype.push with the deobfuscation hook
  const originalPush = EventStream.prototype.push;
  EventStream.prototype.push = function shroudPatchedPush(event: any) {
    const deob = (globalThis as any).__shroudStreamDeobfuscate;
    if (deob && event && typeof event === "object") {
      event = deob(this, event);
    }
    return originalPush.call(this, event);
  };

  // Mark as patched to prevent double-wrapping
  (globalThis as any)[PATCH_MARKER] = true;

}

export default {
  id: "shroud-privacy",
  name: "Shroud",
  register(api: any) {
    // Patch EventStream prototype for streaming deobfuscation (no file I/O)
    patchEventStreamPrototype(api.logger);

    const config = resolveConfig(api.pluginConfig);
    const obfuscator = new Obfuscator(config);

    // Config-as-code: watch ~/.shroud/shroud.config.json for hot-reload
    const configPath = join(process.env.HOME || "/root", ".shroud", "shroud.config.json");
    const configManager = new ConfigManager(configPath, config);
    configManager.onReload((newConfig) => {
      obfuscator.updateConfig(newConfig);
      api.logger?.info("[shroud] Config hot-reloaded from " + configPath);
    });
    configManager.startWatching();

    registerHooks(api, obfuscator);

    // Register shroud_status tool
    api.registerTool({
      name: "shroud_status",
      description:
        "Show plugin diagnostics: entity counts, session info, status",
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
        "Clear all plugin mappings and start a fresh session",
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

    // Single load confirmation — used by test harness to verify plugin loaded.
    // Only logs once per process (suppressed on subsequent agent loads).
    if (!(globalThis as any).__shroudLoadLogged) {
      (globalThis as any).__shroudLoadLogged = true;
      api.logger?.info("[shroud] Plugin loaded.");
    }
  },
};
