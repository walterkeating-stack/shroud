/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 5 hooks:
 * 1. before_prompt_build  (async) -- obfuscate user prompt via prependContext
 * 2. before_llm_send     (async) -- obfuscate LLM input messages + return transformResponse for deobfuscation
 * 3. before_tool_call    (async) -- deobfuscate tool params
 * 4. tool_result_persist  (SYNC) -- obfuscate tool result message
 * 5. message_sending     (async) -- deobfuscate outbound message content (fallback)
 */

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Obfuscator } from "./obfuscator.js";
import { ShroudConfig, ObfuscationResult } from "./types.js";
import { BUILTIN_PATTERNS } from "./detectors/regex.js";

const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";

function dumpStatsFile(obfuscator: Obfuscator): void {
  try {
    const stats = obfuscator.getStats() as Record<string, unknown>;
    stats.updatedAt = new Date().toISOString();
    stats.source = "openclaw";
    stats.pid = process.pid;
    writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2) + "\n");
  } catch {
    // best-effort
  }
}

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

// ---------------------------------------------------------------------------
// Hashing utilities (audit proof hashes)
// ---------------------------------------------------------------------------

function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function safeHash(text: string, salt: string): string {
  return sha256Hex(salt + text);
}

function truncateHash(hash: string, n: number): string {
  return hash.slice(0, n);
}

// ---------------------------------------------------------------------------
// Audit stats types
// ---------------------------------------------------------------------------

interface ObfuscationStats {
  totalEntities: number;
  byCategory: Record<string, number>;
  byRule: Record<string, number>;
  messagesTouched: number;
  blocksTouched: number;
  inputChars: number;
  outputChars: number;
  fakesSample: string[];
}

// ---------------------------------------------------------------------------
// String walking helper
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// obfuscateMessages (original, no stats)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// obfuscateMessagesWithStats (audit-aware)
// ---------------------------------------------------------------------------

function obfuscateMessagesWithStats(
  messages: unknown[],
  obfuscator: Obfuscator,
  config: ShroudConfig,
): { messages: unknown[]; stats: ObfuscationStats } {
  const stats: ObfuscationStats = {
    totalEntities: 0,
    byCategory: {},
    byRule: {},
    messagesTouched: 0,
    blocksTouched: 0,
    inputChars: 0,
    outputChars: 0,
    fakesSample: [],
  };

  const maxFakes = config.auditMaxFakesSample;

  const obfuscatedMessages = messages.map((msg: any) => {
    if (!msg || typeof msg !== "object") return msg;

    if (typeof msg.content === "string") {
      const result = obfuscator.obfuscate(msg.content);
      stats.inputChars += msg.content.length;
      stats.outputChars += result.obfuscated.length;
      if (result.entities.length > 0) {
        stats.messagesTouched++;
        stats.blocksTouched++;
        accumulateStats(stats, result, maxFakes);
      }
      if (result.entities.length === 0) return msg;
      return { ...msg, content: result.obfuscated };
    }

    if (Array.isArray(msg.content)) {
      let msgTouched = false;
      const newContent = msg.content.map((block: any) => {
        if (block && typeof block === "object" && typeof block.text === "string") {
          const result = obfuscator.obfuscate(block.text);
          stats.inputChars += block.text.length;
          stats.outputChars += result.obfuscated.length;
          if (result.entities.length > 0) {
            msgTouched = true;
            stats.blocksTouched++;
            accumulateStats(stats, result, maxFakes);
          }
          if (result.entities.length === 0) return block;
          return { ...block, text: result.obfuscated };
        }
        return block;
      });
      if (msgTouched) stats.messagesTouched++;
      return { ...msg, content: newContent };
    }

    return msg;
  });

  return { messages: obfuscatedMessages, stats };
}

function accumulateStats(
  stats: ObfuscationStats,
  result: ObfuscationResult,
  maxFakes: number,
): void {
  for (const entity of result.entities) {
    stats.totalEntities++;
    stats.byCategory[entity.category] = (stats.byCategory[entity.category] || 0) + 1;
    stats.byRule[entity.detector] = (stats.byRule[entity.detector] || 0) + 1;
  }
  // Collect fake values only (never real values)
  if (maxFakes > 0 && stats.fakesSample.length < maxFakes) {
    for (const fake of Object.values(result.mappingsUsed)) {
      if (stats.fakesSample.length >= maxFakes) break;
      stats.fakesSample.push(fake);
    }
  }
}

// ---------------------------------------------------------------------------
// Audit log emitters
// ---------------------------------------------------------------------------

function emitAuditLog(
  logger: PluginApi["logger"],
  config: ShroudConfig,
  requestId: string,
  stats: ObfuscationStats,
  totalMessages: number,
  concatenatedOriginal: string,
  concatenatedObfuscated: string,
): void {
  const byCatStr = Object.entries(stats.byCategory)
    .map(([k, v]) => `${k}:${v}`)
    .join(",");
  const byRuleStr = Object.entries(stats.byRule)
    .map(([k, v]) => `${k}:${v}`)
    .join(",");

  const modified = stats.inputChars !== stats.outputChars || stats.totalEntities > 0;
  const charDelta = stats.outputChars - stats.inputChars;

  // Always compute proof hashes when proofs enabled
  let proofHashIn = "";
  let proofHashOut = "";
  if (config.auditIncludeProofHashes) {
    proofHashIn = truncateHash(
      safeHash(concatenatedOriginal, config.auditHashSalt),
      config.auditHashTruncate,
    );
    proofHashOut = truncateHash(
      safeHash(concatenatedObfuscated, config.auditHashSalt),
      config.auditHashTruncate,
    );
  }

  if (config.auditLogFormat === "json") {
    const obj: Record<string, unknown> = {
      event: "shroud.audit.before_llm_send",
      req: requestId,
      ts: new Date().toISOString(),
      modified,
      totalEntities: stats.totalEntities,
      messagesTouched: stats.messagesTouched,
      blocksTouched: stats.blocksTouched,
      inputChars: stats.inputChars,
      outputChars: stats.outputChars,
      charDelta,
      byCategory: stats.byCategory,
      byRule: stats.byRule,
    };
    if (config.auditIncludeProofHashes) {
      obj.proofIn = proofHashIn;
      obj.proofOut = proofHashOut;
    }
    if (config.auditMaxFakesSample > 0 && stats.fakesSample.length > 0) {
      obj.fakesSample = stats.fakesSample;
    }
    logger?.info(JSON.stringify(obj));
  } else {
    const parts = [
      `[shroud][audit] OBFUSCATE req=${requestId}`,
      `entities=${stats.totalEntities}`,
      `touched=${stats.messagesTouched}/${totalMessages}`,
      `blocks=${stats.blocksTouched}`,
      `chars=${stats.inputChars}->${stats.outputChars} (delta=${charDelta >= 0 ? "+" : ""}${charDelta})`,
      `modified=${modified ? "YES" : "NO"}`,
      `byCat=${byCatStr || "none"}`,
      `byRule=${byRuleStr || "none"}`,
    ];
    if (config.auditIncludeProofHashes) {
      parts.push(`proof_in=${proofHashIn} proof_out=${proofHashOut}`);
    }
    if (config.auditMaxFakesSample > 0 && stats.fakesSample.length > 0) {
      parts.push(`fakes=[${stats.fakesSample.join("|")}]`);
    }
    logger?.info(parts.join(" | "));
  }
}

function emitDeobfuscationAuditLog(
  logger: PluginApi["logger"],
  config: ShroudConfig,
  requestId: string,
  replacementCount: number,
): void {
  if (config.auditLogFormat === "json") {
    logger?.info(
      JSON.stringify({
        event: "shroud.audit.deobfuscation",
        req: requestId,
        ts: new Date().toISOString(),
        modified: replacementCount > 0,
        deobfuscations: replacementCount,
      }),
    );
  } else {
    logger?.info(
      `[shroud][audit] DEOBFUSCATE req=${requestId} | replacements=${replacementCount} | modified=${replacementCount > 0 ? "YES" : "NO"}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Hook registration
// ---------------------------------------------------------------------------

export function registerHooks(api: PluginApi, obfuscator: Obfuscator): void {
  const config = obfuscator.config;
  const auditActive = config.auditEnabled || config.verboseLogging;

  // -----------------------------------------------------------------------
  // 1. before_prompt_build (async): obfuscate user prompt
  //    Event: { prompt: string, messages?: unknown[], ... }
  //    Return: { prependContext?: string } | void
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any) => {
    const prompt = event?.prompt;
    if (typeof prompt !== "string" || !prompt) return;

    const result = obfuscator.obfuscate(prompt);
    if (result.entities.length === 0) return; // nothing to obfuscate

    dumpStatsFile(obfuscator);
    api.logger?.info(
      `[shroud] before_prompt_build: obfuscated ${result.entities.length} entities`,
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

    const totalMessages = event.messages.length;
    let obfuscatedMessages: unknown[];
    let requestId = "";

    if (auditActive) {
      requestId = randomBytes(8).toString("hex");

      const { messages: msgs, stats } = obfuscateMessagesWithStats(
        event.messages,
        obfuscator,
        config,
      );
      obfuscatedMessages = msgs;

      // Build concatenated texts for proof hashes in local-only variables
      let concatenatedOriginal = "";
      let concatenatedObfuscated = "";
      if (config.auditIncludeProofHashes) {
        for (let i = 0; i < event.messages.length; i++) {
          const orig = event.messages[i];
          const obf = obfuscatedMessages[i] as any;
          if (typeof orig?.content === "string") {
            concatenatedOriginal += orig.content;
            concatenatedObfuscated += (obf?.content ?? "");
          } else if (Array.isArray(orig?.content)) {
            for (let j = 0; j < orig.content.length; j++) {
              const origBlock = orig.content[j];
              const obfBlock = obf?.content?.[j];
              if (typeof origBlock?.text === "string") {
                concatenatedOriginal += origBlock.text;
                concatenatedObfuscated += (obfBlock?.text ?? "");
              }
            }
          }
        }
      }

      try {
        emitAuditLog(
          api.logger,
          config,
          requestId,
          stats,
          totalMessages,
          concatenatedOriginal,
          concatenatedObfuscated,
        );
      } catch {
        // Logging is best-effort — never break obfuscation
      }
    } else {
      obfuscatedMessages = obfuscateMessages(event.messages, obfuscator);
    }

    dumpStatsFile(obfuscator);
    api.logger?.info("[shroud] before_llm_send: obfuscated messages + installed transformResponse");

    // Capture requestId in closure for response audit
    const capturedReqId = requestId;

    return {
      messages: obfuscatedMessages,
      transformResponse: (text: string): string => {
        if (auditActive) {
          try {
            const { text: deobfuscated, replacementCount } =
              obfuscator.deobfuscateWithStats(text);
            if (replacementCount > 0) {
              try {
                emitDeobfuscationAuditLog(
                  api.logger,
                  config,
                  capturedReqId,
                  replacementCount,
                );
              } catch {
                // best-effort
              }
            }
            return deobfuscated;
          } catch {
            return obfuscator.deobfuscate(text);
          }
        }
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

    dumpStatsFile(obfuscator);
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

  // -----------------------------------------------------------------------
  // Tool: shroud-stats — rulebase view with hit counters
  // -----------------------------------------------------------------------
  api.registerTool({
    name: "shroud-stats",
    description: "Show Shroud privacy plugin status: active rules, per-rule hit counts, store size, and config summary.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    handler: async () => {
      const stats = obfuscator.config;
      const overrides = stats.detectorOverrides;
      const { ruleHits, storeMappings, audit } = obfuscator.getStats() as any;

      // Build rule table: all built-in rules with status + hits
      const rules = BUILTIN_PATTERNS.map((p) => {
        const ov = overrides[p.name];
        const enabled = ov?.enabled !== false;
        const confidence = ov?.confidence ?? p.confidence;
        const hits = ruleHits[`regex:${p.name}`] ?? 0;
        return { name: p.name, category: p.category, enabled, confidence, hits };
      });

      // Sort by hits descending
      rules.sort((a, b) => b.hits - a.hits);

      // Format as text table
      const maxName = Math.max(...rules.map((r) => r.name.length), 4);
      const maxCat = Math.max(...rules.map((r) => r.category.length), 8);
      const header = `${"Rule".padEnd(maxName)}  ${"Category".padEnd(maxCat)}  Status    Conf   Hits`;
      const sep = "─".repeat(header.length);
      const rows = rules.map((r) => {
        const status = r.enabled ? "active" : "DISABLED";
        const bar = r.hits > 0 ? " " + "█".repeat(Math.min(Math.ceil(Math.log2(r.hits + 1)), 16)) : "";
        return `${r.name.padEnd(maxName)}  ${r.category.padEnd(maxCat)}  ${status.padEnd(8)}  ${r.confidence.toFixed(2).padStart(4)}  ${String(r.hits).padStart(5)}${bar}`;
      });

      const lines = [
        `Shroud Rule Hits (since gateway start)`,
        sep,
        header,
        sep,
        ...rows,
        sep,
        `Store: ${storeMappings} active mappings`,
        `Audit: ${stats.auditEnabled || stats.verboseLogging ? "enabled" : "disabled"}`,
      ];

      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  });
}
