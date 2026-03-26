/**
 * Shroud -- OpenClaw privacy plugin.
 *
 * Automatically obfuscates sensitive data before it reaches the LLM
 * and deobfuscates responses before they reach the user.
 */

import { createRequire } from "node:module";
import { resolveConfig } from "./config.js";
import { Obfuscator } from "./obfuscator.js";
import { registerHooks } from "./hooks.js";

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

  if (!EventStream?.prototype?.push) {
    logger?.info(
      "[shroud] Could not locate EventStream class — streaming deobfuscation unavailable",
    );
    return;
  }

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

  logger?.info(
    "[shroud] Patched EventStream.prototype.push — zero-file streaming deobfuscation active",
  );
}

export default {
  id: "shroud-privacy",
  name: "Shroud",
  register(api: any) {
    // Patch EventStream prototype for streaming deobfuscation (no file I/O)
    patchEventStreamPrototype(api.logger);

    const config = resolveConfig(api.pluginConfig);
    const obfuscator = new Obfuscator(config);

    registerHooks(api, obfuscator);

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
