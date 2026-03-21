/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 5 hooks:
 * 1. before_agent_start  (async) -- obfuscate user prompt via prependContext
 * 2. before_llm_send     (async) -- obfuscate LLM input messages + return transformResponse for deobfuscation
 * 3. before_tool_call    (async) -- deobfuscate tool params
 * 4. tool_result_persist  (SYNC) -- obfuscate tool result message
 * 5. message_sending     (async) -- deobfuscate outbound message content (fallback)
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

/**
 * Walk LLM messages array and obfuscate all string content.
 * Messages follow the Anthropic/OpenAI format: array of {role, content} where
 * content can be a string or array of content blocks.
 */
function obfuscateMessages(
  messages: unknown[],
  obfuscator: Obfuscator,
): unknown[] {
  return messages.map((msg: any) => {
    if (!msg || typeof msg !== "object") return msg;
    if (typeof msg.content === "string") {
      const result = obfuscator.obfuscate(msg.content);
      if (result.entities.length === 0) return msg;
      return { ...msg, content: result.obfuscated };
    }
    if (Array.isArray(msg.content)) {
      const newContent = msg.content.map((block: any) => {
        if (block && typeof block === "object" && typeof block.text === "string") {
          const result = obfuscator.obfuscate(block.text);
          if (result.entities.length === 0) return block;
          return { ...block, text: result.obfuscated };
        }
        return block;
      });
      return { ...msg, content: newContent };
    }
    return msg;
  });
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
  // 2. before_llm_send (async): obfuscate LLM input + provide response deobfuscator
  //    Event: { messages: unknown[], ... }
  //    Return: { messages?: unknown[], transformResponse?: (text: string) => string } | void
  //
  //    This is the critical hook: transformResponse is stored globally by OpenClaw
  //    and applied to ALL LLM output — including auto-reply text before WhatsApp
  //    delivery (via normalizeReplyPayload → applyResponseTransform).
  // -----------------------------------------------------------------------
  api.on("before_llm_send", async (event: any) => {
    if (!Array.isArray(event?.messages)) return;

    const obfuscatedMessages = obfuscateMessages(event.messages, obfuscator);

    api.logger?.info("[shroud] before_llm_send: obfuscated messages + installed transformResponse");

    return {
      messages: obfuscatedMessages,
      transformResponse: (text: string): string => {
        return obfuscator.deobfuscate(text);
      },
    };
  });

  // -----------------------------------------------------------------------
  // 3. before_tool_call (async): deobfuscate tool params
  //    Event: { toolName: string, params: Record<string, unknown>, ... }
  //    Return: { params?: Record<string, unknown>, block?: boolean } | void
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.params || typeof event.params !== "object") return;

    const serialized = JSON.stringify(event.params);
    const deobfuscated = obfuscator.deobfuscate(serialized);

    if (serialized === deobfuscated) return; // nothing to deobfuscate

    api.logger?.info(
      `[shroud] before_tool_call(${event.toolName ?? "?"}): deobfuscated params`,
    );

    try {
      return { params: JSON.parse(deobfuscated) };
    } catch {
      api.logger?.warn("[shroud] Failed to parse deobfuscated tool params");
    }
  });

  // -----------------------------------------------------------------------
  // 4. tool_result_persist (SYNC -- no async!): obfuscate tool result
  //    Event: { toolName?, toolCallId?, message: AgentMessage, ... }
  //    Return: { message?: AgentMessage } | void
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
  // 5. message_sending (async): deobfuscate outbound message content
  //    Fallback for non-auto-reply paths (e.g. message tool, TUI delivery).
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
