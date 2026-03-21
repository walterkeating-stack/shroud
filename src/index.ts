/**
 * Shroud -- OpenClaw privacy plugin.
 *
 * Automatically obfuscates sensitive data before it reaches the LLM
 * and deobfuscates responses before they reach the user.
 */

import { resolveConfig } from "./config.js";
import { Obfuscator } from "./obfuscator.js";
import { registerHooks } from "./hooks.js";

export default {
  id: "openclaw-shroud",
  name: "Shroud",
  register(api: any) {
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
