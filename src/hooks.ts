/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 6 hooks + 1 transport interceptor (version-adaptive):
 * 1. before_prompt_build   (async) -- obfuscate user prompt via prependContext
 * 2. before_message_write  (SYNC)  -- obfuscate every message written to the session transcript
 * 3. before_llm_send       (async) -- obfuscate LLM messages + install transformResponse (>=2026.3.14)
 * 4. before_tool_call      (async) -- deobfuscate tool params (+ depth tracking)
 * 5. tool_result_persist   (SYNC)  -- obfuscate tool result message
 * 6. message_sending       (async) -- deobfuscate outbound message content
 * 7. Transport interceptor         -- wraps Slack WebClient.apiCall for universal deobfuscation
 *
 * The transport interceptor is the universal fallback: it deobfuscates Slack
 * messages at the API-call level, independent of which OpenClaw hooks fire.
 * On >=2026.3.14, transformResponse handles deobfuscation first (for ALL
 * channels); the transport interceptor is a no-op since the text is already
 * deobfuscated.  On older versions where message_sending doesn't fire for
 * Slack, the interceptor catches it.
 */

import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { Obfuscator } from "./obfuscator.js";
import { ObfuscationResult } from "./types.js";
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
// Audit log emitter — per-message (used by before_message_write)
// ---------------------------------------------------------------------------

function emitObfuscationAudit(
  logger: PluginApi["logger"],
  config: { auditLogFormat: string; auditIncludeProofHashes: boolean; auditHashSalt: string; auditHashTruncate: number; auditMaxFakesSample: number },
  requestId: string,
  result: ObfuscationResult,
  inputText: string,
  outputText: string,
): void {
  const byCat: Record<string, number> = {};
  const byRule: Record<string, number> = {};
  for (const e of result.entities) {
    byCat[e.category] = (byCat[e.category] || 0) + 1;
    byRule[e.detector] = (byRule[e.detector] || 0) + 1;
  }

  const modified = result.entities.length > 0;
  const charDelta = outputText.length - inputText.length;

  let proofIn = "";
  let proofOut = "";
  if (config.auditIncludeProofHashes) {
    proofIn = truncateHash(safeHash(inputText, config.auditHashSalt), config.auditHashTruncate);
    proofOut = truncateHash(safeHash(outputText, config.auditHashSalt), config.auditHashTruncate);
  }

  const fakesSample: string[] = [];
  if (config.auditMaxFakesSample > 0) {
    for (const fake of Object.values(result.mappingsUsed)) {
      if (fakesSample.length >= config.auditMaxFakesSample) break;
      fakesSample.push(fake);
    }
  }

  if (config.auditLogFormat === "json") {
    const obj: Record<string, unknown> = {
      event: "shroud.audit.obfuscate",
      req: requestId,
      ts: new Date().toISOString(),
      modified,
      totalEntities: result.entities.length,
      inputChars: inputText.length,
      outputChars: outputText.length,
      charDelta,
      byCategory: byCat,
      byRule,
    };
    if (config.auditIncludeProofHashes) {
      obj.proofIn = proofIn;
      obj.proofOut = proofOut;
    }
    if (fakesSample.length > 0) {
      obj.fakesSample = fakesSample;
    }
    logger?.info(JSON.stringify(obj));
  } else {
    const byCatStr = Object.entries(byCat).map(([k, v]) => `${k}:${v}`).join(",");
    const byRuleStr = Object.entries(byRule).map(([k, v]) => `${k}:${v}`).join(",");
    const parts = [
      `[shroud][audit] OBFUSCATE req=${requestId}`,
      `entities=${result.entities.length}`,
      `chars=${inputText.length}->${outputText.length} (delta=${charDelta >= 0 ? "+" : ""}${charDelta})`,
      `modified=${modified ? "YES" : "NO"}`,
      `byCat=${byCatStr || "none"}`,
      `byRule=${byRuleStr || "none"}`,
    ];
    if (config.auditIncludeProofHashes) {
      parts.push(`proof_in=${proofIn} proof_out=${proofOut}`);
    }
    if (fakesSample.length > 0) {
      parts.push(`fakes=[${fakesSample.join("|")}]`);
    }
    logger?.info(parts.join(" | "));
  }
}

function emitDeobfuscationAudit(
  logger: PluginApi["logger"],
  config: { auditLogFormat: string },
  requestId: string,
  replacementCount: number,
): void {
  if (config.auditLogFormat === "json") {
    logger?.info(JSON.stringify({
      event: "shroud.audit.deobfuscate",
      req: requestId,
      ts: new Date().toISOString(),
      modified: replacementCount > 0,
      deobfuscations: replacementCount,
    }));
  } else {
    logger?.info(
      `[shroud][audit] DEOBFUSCATE req=${requestId} | replacements=${replacementCount} | modified=${replacementCount > 0 ? "YES" : "NO"}`,
    );
  }
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
// Transport-level deobfuscation interceptor (fallback for all versions)
// ---------------------------------------------------------------------------

/**
 * Wraps the Slack WebClient.prototype.apiCall to deobfuscate outbound message
 * text before it hits the Slack API.  This is the universal fallback that works
 * on ANY OpenClaw version — it doesn't depend on hook dispatch at all.
 *
 * The @slack/web-api package is CJS and already loaded by OpenClaw, so it lives
 * in require.cache.  We find it there, wrap the prototype once, done.
 */
function installTransportInterceptor(
  obfuscator: Obfuscator,
  logger: PluginApi["logger"],
): void {
  try {
    const esmRequire = createRequire(import.meta.url);
    const cache = esmRequire.cache;
    if (!cache) return;

    for (const key of Object.keys(cache)) {
      if (!key.includes("@slack/web-api")) continue;
      const mod = cache[key];
      const WebClient = mod?.exports?.WebClient;
      if (typeof WebClient !== "function") continue;

      const proto = WebClient.prototype;
      if (typeof proto.apiCall !== "function") continue;
      if ((proto as any).__shroudPatched) return; // already wrapped

      const origApiCall = proto.apiCall;

      proto.apiCall = async function shroudApiCall(
        method: string,
        options?: Record<string, unknown>,
      ) {
        if (
          (method === "chat.postMessage" || method === "chat.update") &&
          options
        ) {
          // Deobfuscate the plain-text fallback
          if (typeof options.text === "string") {
            const original = options.text as string;
            const deobfuscated = obfuscator.deobfuscate(original);
            if (deobfuscated !== original) {
              options = { ...options, text: deobfuscated };
              logger?.info(
                `[shroud][transport] deobfuscated Slack ${method}`,
              );
            }
          }
          // Deobfuscate blocks (rich text) — walk all text elements
          if (Array.isArray(options.blocks)) {
            const json = JSON.stringify(options.blocks);
            const deobJson = obfuscator.deobfuscate(json);
            if (deobJson !== json) {
              try {
                options = { ...options, blocks: JSON.parse(deobJson) };
              } catch {
                // If JSON parse fails, leave blocks unchanged
              }
            }
          }
        }
        return origApiCall.call(this, method, options);
      };

      (proto as any).__shroudPatched = true;
      logger?.info(
        "[shroud] Installed Slack transport interceptor (universal deobfuscation fallback)",
      );
      return;
    }

    logger?.info(
      "[shroud] Slack WebClient not found in require.cache — transport interceptor not installed (hooks-only mode)",
    );
  } catch (err) {
    logger?.warn(
      `[shroud] Failed to install transport interceptor: ${String(err)}`,
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
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any) => {
    // Reset tool depth at the start of each turn — tool calls from the
    // previous turn are complete, so the counter should not carry over.
    if (obfuscator.toolDepth > 0) {
      obfuscator.resetToolDepth();
    }

    const prompt = event?.prompt;
    if (typeof prompt !== "string" || !prompt) return;

    const result = obfuscator.obfuscate(prompt);
    if (result.entities.length === 0) return;

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
  // 2. before_message_write (SYNC): obfuscate every message written to session
  //    This ensures the LLM always sees obfuscated history, even on platforms
  //    that don't support before_llm_send.
  // -----------------------------------------------------------------------
  api.on("before_message_write", (event: any) => {
    if (!event?.message || typeof event.message !== "object") return;

    const msg = event.message;

    // Obfuscate string content
    if (typeof msg.content === "string") {
      const result = obfuscator.obfuscate(msg.content);
      if (result.entities.length === 0) return;
      dumpStatsFile(obfuscator);
      if (auditActive) {
        try {
          emitObfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), result, msg.content, result.obfuscated);
        } catch { /* best-effort */ }
      }
      return { message: { ...msg, content: result.obfuscated } };
    }

    // Obfuscate array-of-blocks content
    if (Array.isArray(msg.content)) {
      let changed = false;
      const allResults: ObfuscationResult[] = [];
      const newContent = msg.content.map((block: any) => {
        if (block && typeof block === "object" && typeof block.text === "string") {
          const result = obfuscator.obfuscate(block.text);
          if (result.entities.length > 0) {
            changed = true;
            allResults.push(result);
            return { ...block, text: result.obfuscated };
          }
        }
        return block;
      });
      if (!changed) return;
      dumpStatsFile(obfuscator);
      if (auditActive) {
        for (const result of allResults) {
          try {
            const origText = Object.keys(result.mappingsUsed).join(" ");
            emitObfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), result, origText, result.obfuscated);
          } catch { /* best-effort */ }
        }
      }
      return { message: { ...msg, content: newContent } };
    }
  });

  // -----------------------------------------------------------------------
  // 3. before_llm_send (async): obfuscate LLM context + install transformResponse
  //    Available on OpenClaw >=2026.3.14. Silently ignored on older versions.
  //    This is the most reliable deobfuscation path — transformResponse catches
  //    ALL LLM output text including streaming deltas.
  // -----------------------------------------------------------------------
  api.on("before_llm_send", async (event: any) => {
    const messages = event?.messages;
    if (!Array.isArray(messages)) return;

    // Obfuscate all string content in the message array
    let totalEntities = 0;
    const obfuscatedMessages = messages.map((msg: any) => {
      if (!msg || typeof msg !== "object") return msg;
      const walked = walkStrings(msg.content, (s: string) => {
        const result = obfuscator.obfuscate(s);
        totalEntities += result.entities.length;
        return result.obfuscated;
      });
      if (walked === msg.content) return msg;
      return { ...msg, content: walked };
    });

    if (totalEntities > 0) {
      dumpStatsFile(obfuscator);
      api.logger?.info(
        `[shroud] before_llm_send: obfuscated ${totalEntities} entities in ${messages.length} messages`,
      );
    }

    // Install transformResponse — this deobfuscates LLM output text.
    // It's a synchronous function called on every response chunk.
    const requestId = randomBytes(8).toString("hex");
    const transformResponse = (text: string): string => {
      if (auditActive) {
        const { text: deobfuscated, replacementCount } = obfuscator.deobfuscateWithStats(text);
        if (deobfuscated !== text) {
          try {
            emitDeobfuscationAudit(api.logger, config, requestId, replacementCount);
          } catch { /* best-effort */ }
          dumpStatsFile(obfuscator);
        }
        return deobfuscated;
      }
      return obfuscator.deobfuscate(text);
    };

    return {
      messages: totalEntities > 0 ? obfuscatedMessages : undefined,
      transformResponse,
    };
  });

  // -----------------------------------------------------------------------
  // 4. before_tool_call (async): deobfuscate tool params + track depth
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.params || typeof event.params !== "object") return;

    // Tool chain depth tracking
    const depth = obfuscator.enterToolCall();
    if (depth > config.maxToolDepth) {
      api.logger?.warn(
        `[shroud][depth] Tool chain depth ${depth} exceeds max ${config.maxToolDepth} — possible infinite recursion`,
      );
    }
    if (depth > 1) {
      api.logger?.info(
        `[shroud][depth] Nested tool call at depth ${depth}: ${event.toolName ?? "?"}`,
      );
    }

    const serialized = JSON.stringify(event.params);
    const deobfuscated = obfuscator.deobfuscate(serialized);

    if (serialized === deobfuscated) return;

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
  // 5. tool_result_persist (SYNC): obfuscate tool result message
  // -----------------------------------------------------------------------
  api.on("tool_result_persist", (event: any) => {
    if (!event?.message) return;

    // Exit tool depth
    obfuscator.exitToolCall();

    const obfuscated = walkStrings(event.message, (s) => {
      const result = obfuscator.obfuscate(s);
      return result.obfuscated;
    });

    dumpStatsFile(obfuscator);
    return { message: obfuscated };
  });

  // -----------------------------------------------------------------------
  // 6. message_sending (async): deobfuscate outbound message content
  //    Fallback for versions without before_llm_send/transformResponse.
  // -----------------------------------------------------------------------
  api.on("message_sending", async (event: any) => {
    if (typeof event?.content !== "string") return;

    if (auditActive) {
      const { text: deobfuscated, replacementCount } = obfuscator.deobfuscateWithStats(event.content);
      if (deobfuscated === event.content) return;
      try {
        emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), replacementCount);
      } catch { /* best-effort */ }
      dumpStatsFile(obfuscator);
      return { content: deobfuscated };
    }

    const deobfuscated = obfuscator.deobfuscate(event.content);
    if (deobfuscated === event.content) return;

    api.logger?.info("[shroud] message_sending: deobfuscated outbound message");
    dumpStatsFile(obfuscator);

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
      const obStats = obfuscator.getStats() as any;

      const rules = BUILTIN_PATTERNS.map((p) => {
        const ov = overrides[p.name];
        const enabled = ov?.enabled !== false;
        const confidence = ov?.confidence ?? p.confidence;
        const hits = obStats.ruleHits[`regex:${p.name}`] ?? 0;
        return { name: p.name, category: p.category, enabled, confidence, hits };
      });

      rules.sort((a, b) => b.hits - a.hits);

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
        `Store: ${obStats.storeMappings} active mappings`,
        `Audit: ${stats.auditEnabled || stats.verboseLogging ? "enabled" : "disabled"}`,
        `Redaction: ${stats.redactionLevel}`,
      ];

      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  });

  // -----------------------------------------------------------------------
  // 7. Transport interceptor: universal deobfuscation fallback
  //    Wraps Slack WebClient.apiCall so outbound messages are deobfuscated
  //    regardless of which OpenClaw hooks fire (or don't).
  // -----------------------------------------------------------------------
  installTransportInterceptor(obfuscator, api.logger);
}
