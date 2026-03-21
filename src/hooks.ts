/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 4 hooks:
 * 1. before_agent_start  (async) -- obfuscate user message content
 * 2. before_tool_call    (async) -- deobfuscate tool arguments
 * 3. tool_result_persist  (SYNC) -- obfuscate tool result content
 * 4. message_sending     (async) -- deobfuscate assistant reply content
 */

import { Obfuscator } from "./obfuscator.js";

// Generic types for the OpenClaw API (we don't have the SDK as a dependency)
interface PluginApi {
  on(event: string, handler: (...args: any[]) => any): void;
  registerTool(tool: {
    name: string;
    description: string;
    inputSchema: object;
    handler: (input: any) => Promise<any>;
  }): void;
  pluginConfig?: unknown;
  logger?: {
    info(...args: any[]): void;
    warn(...args: any[]): void;
    error(...args: any[]): void;
  };
}

export function registerHooks(api: PluginApi, obfuscator: Obfuscator): void {
  // -----------------------------------------------------------------------
  // 1. before_agent_start (async): obfuscate user message content
  // -----------------------------------------------------------------------
  api.on("before_agent_start", async (event: any) => {
    if (!event?.messages) return event;

    for (const message of event.messages) {
      if (message.role !== "user") continue;

      if (typeof message.content === "string") {
        const result = obfuscator.obfuscate(message.content);
        message.content = result.obfuscated;
      } else if (Array.isArray(message.content)) {
        for (const block of message.content) {
          if (block.type === "text" && typeof block.text === "string") {
            const result = obfuscator.obfuscate(block.text);
            block.text = result.obfuscated;
          }
        }
      }
    }

    return event;
  });

  // -----------------------------------------------------------------------
  // 2. before_tool_call (async): deobfuscate tool arguments
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.arguments) return event;

    if (typeof event.arguments === "string") {
      event.arguments = obfuscator.deobfuscate(event.arguments);
    } else if (typeof event.arguments === "object" && event.arguments !== null) {
      // Stringify -> deobfuscate -> parse back
      const serialized = JSON.stringify(event.arguments);
      const deobfuscated = obfuscator.deobfuscate(serialized);
      try {
        event.arguments = JSON.parse(deobfuscated);
      } catch {
        // If parse fails, leave as-is
        api.logger?.warn("[shroud] Failed to parse deobfuscated tool arguments");
      }
    }

    return event;
  });

  // -----------------------------------------------------------------------
  // 3. tool_result_persist (SYNC -- no async!): obfuscate tool result content
  // -----------------------------------------------------------------------
  api.on("tool_result_persist", (event: any) => {
    if (!event?.content) return event;

    if (typeof event.content === "string") {
      const result = obfuscator.obfuscate(event.content);
      event.content = result.obfuscated;
    } else if (Array.isArray(event.content)) {
      for (const block of event.content) {
        if (block.type === "text" && typeof block.text === "string") {
          const result = obfuscator.obfuscate(block.text);
          block.text = result.obfuscated;
        }
      }
    }

    return event;
  });

  // -----------------------------------------------------------------------
  // 4. message_sending (async): deobfuscate assistant reply content
  // -----------------------------------------------------------------------
  api.on("message_sending", async (event: any) => {
    if (!event?.message) return event;

    const message = event.message;

    if (typeof message.content === "string") {
      message.content = obfuscator.deobfuscate(message.content);
    } else if (Array.isArray(message.content)) {
      for (const block of message.content) {
        if (block.type === "text" && typeof block.text === "string") {
          block.text = obfuscator.deobfuscate(block.text);
        }
      }
    }

    return event;
  });
}
