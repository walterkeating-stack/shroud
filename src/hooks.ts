/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 4 hooks:
 * 1. before_agent_start  (async) -- obfuscate user prompt
 * 2. before_tool_call    (async) -- deobfuscate tool arguments
 * 3. tool_result_persist  (SYNC) -- obfuscate tool result message
 * 4. message_sending     (async) -- deobfuscate outbound message content
 */

import { Obfuscator } from "./obfuscator.js";

// Generic types for the OpenClaw API (we don't have the SDK as a dependency)
export interface PluginApi {
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

/**
 * Deep-walk an unknown message structure and obfuscate/deobfuscate all
 * string leaves.  OpenClaw message payloads can be a plain string, an
 * array of content blocks, or a nested object — this handles all three.
 */
function walkStrings(
  value: unknown,
  fn: (s: string) => string,
): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (typeof item === "object" && item !== null && "text" in item && typeof (item as any).text === "string") {
        return { ...item, text: fn((item as any).text) };
      }
      return walkStrings(item, fn);
    });
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string") {
        out[k] = fn(v);
      } else {
        out[k] = v; // don't recurse arbitrarily into unknown objects
      }
    }
    return out;
  }
  return value;
}

export function registerHooks(api: PluginApi, obfuscator: Obfuscator): void {
  // -----------------------------------------------------------------------
  // 1. before_agent_start (async): obfuscate user prompt
  //    Event: { prompt: string, ... }
  //    Return: { prependContext?: string } | void
  // -----------------------------------------------------------------------
  api.on("before_agent_start", async (event: any) => {
    const prompt = event?.prompt;
    if (typeof prompt !== "string" || !prompt) return;

    const result = obfuscator.obfuscate(prompt);
    if (result.entities.length === 0) return; // nothing to obfuscate

    api.logger?.info(
      `[shroud] before_agent_start: obfuscated ${result.entities.length} entities`,
    );

    // We can't replace the prompt directly — instead prepend a context
    // block that contains the obfuscated version and instructs the LLM
    // to use the sanitized version.
    return {
      prependContext: [
        "--- SHROUD PRIVACY LAYER ---",
        "The following user message has been privacy-filtered.",
        "Use ONLY the sanitized version below. Do NOT reference the original values.",
        "",
        result.obfuscated,
        "--- END SHROUD ---",
      ].join("\n"),
    };
  });

  // -----------------------------------------------------------------------
  // 2. before_tool_call (async): deobfuscate tool arguments
  //    Event: { toolName, arguments, ... }
  //    Return: modified event | void
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.arguments) return event;

    if (typeof event.arguments === "string") {
      event.arguments = obfuscator.deobfuscate(event.arguments);
    } else if (typeof event.arguments === "object" && event.arguments !== null) {
      const serialized = JSON.stringify(event.arguments);
      const deobfuscated = obfuscator.deobfuscate(serialized);
      try {
        event.arguments = JSON.parse(deobfuscated);
      } catch {
        api.logger?.warn("[shroud] Failed to parse deobfuscated tool arguments");
      }
    }

    return event;
  });

  // -----------------------------------------------------------------------
  // 3. tool_result_persist (SYNC -- no async!): obfuscate tool result
  //    Event: { toolName?, toolCallId?, message: unknown, ... }
  //    Return: { message: unknown } | void
  // -----------------------------------------------------------------------
  api.on("tool_result_persist", (event: any) => {
    if (!event?.message) return;

    const obfuscated = walkStrings(event.message, (s) => {
      const result = obfuscator.obfuscate(s);
      return result.obfuscated;
    });

    return { message: obfuscated };
  });

  // -----------------------------------------------------------------------
  // 4. message_sending (async): deobfuscate outbound message
  //    Event: { to: string, content: string, metadata?, ... }
  //    Return: { content?: string } | void
  // -----------------------------------------------------------------------
  api.on("message_sending", async (event: any) => {
    if (typeof event?.content !== "string") return;

    const deobfuscated = obfuscator.deobfuscate(event.content);
    if (deobfuscated === event.content) return; // nothing changed

    api.logger?.info("[shroud] message_sending: deobfuscated outbound message");

    return { content: deobfuscated };
  });
}
