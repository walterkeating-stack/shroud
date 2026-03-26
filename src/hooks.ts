/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 5 hooks + 1 global streaming deobfuscation hook:
 * 1. before_prompt_build   (async) -- obfuscate user prompt via prependContext
 * 2. before_message_write  (SYNC)  -- bidirectional: obfuscate non-assistant,
 *                                     DEOBFUSCATE assistant messages
 * 3. before_tool_call      (async) -- deobfuscate tool params (+ depth tracking)
 * 4. tool_result_persist   (SYNC)  -- obfuscate tool result message
 * 5. message_sending       (async) -- deobfuscate outbound message content
 * 6. globalThis.__shroudStreamDeobfuscate -- global function called by pi-ai's
 *                                     patched EventStream.push() to deobfuscate
 *                                     streaming text_delta events from ALL LLM
 *                                     providers before OpenClaw processes them
 */

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Obfuscator } from "./obfuscator.js";
import { ObfuscationResult } from "./types.js";
import { BUILTIN_PATTERNS } from "./detectors/regex.js";

const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";

function getSharedObfuscator(fallback: Obfuscator): Obfuscator {
  return (globalThis as any).__shroudObfuscator || fallback;
}

function dumpStatsFile(fallback: Obfuscator): void {
  try {
    const ob = getSharedObfuscator(fallback);
    const stats = ob.getStats() as Record<string, unknown>;
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
// Hook registration
// ---------------------------------------------------------------------------

export function registerHooks(api: PluginApi, obfuscator: Obfuscator): void {
  // Share the Obfuscator instance across all plugin instances via globalThis.
  // OpenClaw loads plugins per-agent, so before_prompt_build may fire on one
  // instance while message_sending fires on another (via the delivery subsystem).
  // Without sharing, the delivery instance has an empty mapping store and
  // cannot deobfuscate CGNAT surrogates in outbound channel messages.
  if (process.env.NODE_ENV !== "test") {
    const g = globalThis as any;
    if (g.__shroudObfuscator) {
      obfuscator = g.__shroudObfuscator;
    } else {
      g.__shroudObfuscator = obfuscator;
    }
  }

  // All hook closures must use the shared obfuscator, not the local parameter.
  // OpenClaw loads the plugin multiple times; only one instance has the mappings.
  const ob = () => getSharedObfuscator(obfuscator);
  const config = ob().config;
  const auditActive = config.auditEnabled || config.verboseLogging;

  // -----------------------------------------------------------------------
  // 1. before_prompt_build (async): obfuscate user prompt
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any) => {

    // Reset tool depth at the start of each turn — tool calls from the
    // previous turn are complete, so the counter should not carry over.
    if (ob().toolDepth > 0) {
      ob().resetToolDepth();
    }

    const prompt = event?.prompt;
    if (typeof prompt !== "string" || !prompt) return;

    const result = ob().obfuscate(prompt);
    if (result.entities.length === 0) return;

    dumpStatsFile(obfuscator);
    api.logger?.info(
      `[shroud] before_prompt_build: obfuscated ${result.entities.length} entities`,
    );

    return {
      prompt: result.obfuscated,
    };
  });

  // -----------------------------------------------------------------------
  // 2. before_message_write (SYNC): bidirectional privacy filter
  //    - User/system messages: obfuscate (protect PII from LLM context)
  //    - Assistant messages: deobfuscate (replace fakes with real values)
  //
  //    This is the universal deobfuscation point — OpenClaw delivers the
  //    message returned by this hook to ALL channels (Slack, WhatsApp, etc.)
  //    Tradeoff: deobfuscated assistant text is stored in the transcript.
  //    On the next turn, before_message_write re-obfuscates when those
  //    messages (now with real PII) are written back into context.
  // -----------------------------------------------------------------------
  api.on("before_message_write", (event: any) => {
    if (!event?.message || typeof event.message !== "object") return;

    const msg = event.message;
    const role = msg.role ?? "";

    // --- Assistant messages: DEOBFUSCATE (fakes → real values) ---
    if (role === "assistant") {
      if (typeof msg.content === "string") {
        const { text: deobfuscated, replacementCount } = ob().deobfuscateWithStats(msg.content);
        if (deobfuscated === msg.content) return;
        api.logger?.info("[shroud] before_message_write: deobfuscated assistant message");
        if (auditActive && replacementCount > 0) {
          try { emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), replacementCount); } catch {}
        }
        dumpStatsFile(obfuscator);
        return { message: { ...msg, content: deobfuscated } };
      }
      if (Array.isArray(msg.content)) {
        let changed = false;
        const newContent = msg.content.map((block: any) => {
          if (block && typeof block === "object") {
            // Handle blocks with .text (text content blocks)
            if (typeof block.text === "string") {
              const deobfuscated = ob().deobfuscate(block.text);
              if (deobfuscated !== block.text) {
                changed = true;
                return { ...block, text: deobfuscated };
              }
            }
            // Handle blocks with .content as string (tool_result blocks)
            if (typeof block.content === "string") {
              const deobfuscated = ob().deobfuscate(block.content);
              if (deobfuscated !== block.content) {
                changed = true;
                return { ...block, content: deobfuscated };
              }
            }
            // Handle blocks with .content as array (nested content blocks)
            if (Array.isArray(block.content)) {
              let innerChanged = false;
              const newInner = block.content.map((inner: any) => {
                if (inner && typeof inner === "object" && typeof inner.text === "string") {
                  const deobfuscated = ob().deobfuscate(inner.text);
                  if (deobfuscated !== inner.text) {
                    innerChanged = true;
                    return { ...inner, text: deobfuscated };
                  }
                }
                return inner;
              });
              if (innerChanged) {
                changed = true;
                return { ...block, content: newInner };
              }
            }
          }
          return block;
        });
        if (!changed) return;
        api.logger?.info("[shroud] before_message_write: deobfuscated assistant blocks");
        dumpStatsFile(obfuscator);
        return { message: { ...msg, content: newContent } };
      }
      return;
    }

    // --- Non-assistant messages: OBFUSCATE (real values → fakes) ---
    if (typeof msg.content === "string") {
      const result = ob().obfuscate(msg.content);
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
        if (block && typeof block === "object") {
          // Handle blocks with .text (text content blocks)
          if (typeof block.text === "string") {
            const result = ob().obfuscate(block.text);
            if (result.entities.length > 0) {
              changed = true;
              allResults.push(result);
              return { ...block, text: result.obfuscated };
            }
          }
          // Handle blocks with .content as string (tool_result blocks)
          if (typeof block.content === "string") {
            const result = ob().obfuscate(block.content);
            if (result.entities.length > 0) {
              changed = true;
              allResults.push(result);
              return { ...block, content: result.obfuscated };
            }
          }
          // Handle blocks with .content as array (nested content blocks)
          if (Array.isArray(block.content)) {
            let innerChanged = false;
            const innerResults: ObfuscationResult[] = [];
            const newInner = block.content.map((inner: any) => {
              if (inner && typeof inner === "object" && typeof inner.text === "string") {
                const result = ob().obfuscate(inner.text);
                if (result.entities.length > 0) {
                  innerChanged = true;
                  innerResults.push(result);
                  return { ...inner, text: result.obfuscated };
                }
              }
              return inner;
            });
            if (innerChanged) {
              changed = true;
              allResults.push(...innerResults);
              return { ...block, content: newInner };
            }
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
  // 3. before_tool_call (async): deobfuscate tool params + track depth
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.params || typeof event.params !== "object") return;

    // Tool chain depth tracking
    const depth = ob().enterToolCall();
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
    const deobfuscated = ob().deobfuscate(serialized);

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
  // 4. tool_result_persist (SYNC): obfuscate tool result message
  // -----------------------------------------------------------------------
  api.on("tool_result_persist", (event: any) => {
    if (!event?.message) return;

    // Exit tool depth
    ob().exitToolCall();

    const obfuscated = walkStrings(event.message, (s) => {
      const result = ob().obfuscate(s);
      return result.obfuscated;
    });

    dumpStatsFile(obfuscator);
    return { message: obfuscated };
  });

  // -----------------------------------------------------------------------
  // 5. message_sending (async): deobfuscate outbound message content
  //    Handles both string content and structured blocks/arrays (Slack
  //    sends blocks in the first call, text in the second).
  // -----------------------------------------------------------------------
  api.on("message_sending", async (event: any) => {
    if (!event?.content) return;

    // String content — direct deobfuscation
    if (typeof event.content === "string") {
      if (auditActive) {
        const { text: deobfuscated, replacementCount } = ob().deobfuscateWithStats(event.content);
        if (deobfuscated === event.content) return;
        try {
          emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), replacementCount);
        } catch { /* best-effort */ }
        dumpStatsFile(obfuscator);
        return { content: deobfuscated };
      }

      const deobfuscated = ob().deobfuscate(event.content);
      if (deobfuscated === event.content) return;

      api.logger?.info("[shroud] message_sending: deobfuscated outbound message");
      dumpStatsFile(obfuscator);
      return { content: deobfuscated };
    }

    // Array content (blocks) — walk and deobfuscate all text leaves
    if (Array.isArray(event.content)) {
      let changed = false;
      const newContent = event.content.map((block: any) => {
        if (block && typeof block === "object") {
          if (typeof block.text === "string") {
            const deob = ob().deobfuscate(block.text);
            if (deob !== block.text) { changed = true; return { ...block, text: deob }; }
          }
          if (typeof block.content === "string") {
            const deob = ob().deobfuscate(block.content);
            if (deob !== block.content) { changed = true; return { ...block, content: deob }; }
          }
        }
        return block;
      });
      if (!changed) return;
      api.logger?.info("[shroud] message_sending: deobfuscated outbound blocks");
      dumpStatsFile(obfuscator);
      return { content: newContent };
    }
  });

  // -----------------------------------------------------------------------
  // Tool: shroud-stats — rulebase view with hit counters
  // -----------------------------------------------------------------------
  api.registerTool({
    name: "shroud-stats",
    description: "Show Shroud privacy plugin status: active rules, per-rule hit counts, store size, and config summary.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    handler: async () => {
      const stats = ob().config;
      const overrides = stats.detectorOverrides;
      const obStats = ob().getStats() as any;

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
  // 6. LLM response interceptor: global deobfuscation hook
  //    Set a global function that pi-ai's EventStream.push() calls to
  //    deobfuscate streaming text events. Uses buffered deobfuscation
  //    (accumulates text per-stream, deobfuscates the buffer, emits delta).
  //    Works for ALL LLM providers across ALL channels.
  // -----------------------------------------------------------------------
  // Deobfuscation strategy: accumulate text_delta chunks per-stream.
  // On each chunk, deobfuscate the full buffer and emit the delta between
  // what was previously emitted and the current deobfuscated result.
  // If deobfuscation makes text shorter (fake→real), emit empty for
  // overflow chunks. Partial fakes may briefly appear during streaming
  // but the final message will be correct.
  const SHROUD_BUF = Symbol("shroudStreamBuf");

  (globalThis as any).__shroudStreamDeobfuscate = (stream: any, event: any) => {
    const isTextDelta = event.type === "text_delta";
    const isMessageUpdateTextDelta = event.type === "message_update" &&
      event.assistantMessageEvent?.type === "text_delta";

    if (isTextDelta || isMessageUpdateTextDelta) {
      let buf = stream[SHROUD_BUF];
      if (!buf) { buf = { raw: "", emitted: 0, deobCount: 0 }; stream[SHROUD_BUF] = buf; }

      const src = isMessageUpdateTextDelta ? event.assistantMessageEvent : event;
      const chunk = typeof src.delta === "string" ? src.delta
        : typeof src.text === "string" ? src.text : "";
      if (!chunk) return event;

      buf.raw += chunk;
      const deob = ob().deobfuscate(buf.raw);

      // Emit the new portion of the deobfuscated buffer
      let newText: string;
      if (deob.length > buf.emitted) {
        newText = deob.slice(buf.emitted);
        buf.emitted = deob.length;
      } else {
        // Deobfuscated text is shorter — fake was replaced with shorter real.
        // Emit empty for this chunk; the accumulated delivery text already
        // has some fake chars that will be corrected on message_end.
        newText = "";
        buf.emitted = deob.length;
      }

      if (newText !== chunk) {
        buf.deobCount = (buf.deobCount || 0) + 1;
        // Also increment the obfuscator's counter directly
        const obInst = ob() as any;
        if (typeof obInst._deobfuscationEvents === "number") {
          obInst._deobfuscationEvents++;
          obInst._totalReplacementsDeobfuscated++;
        }
        if (isMessageUpdateTextDelta) {
          const patched = { ...src, delta: newText };
          if (typeof src.text === "string") patched.text = newText;
          event = { ...event, assistantMessageEvent: patched };
        } else {
          event = { ...event, delta: newText };
          if (typeof event.text === "string") event.text = newText;
        }
      }
    }

    // On message_end/done: deobfuscate the full content in the partial/message
    // to correct any partial fakes from streaming
    const isEnd = event.type === "done" || event.type === "message_end" ||
      event.type === "error" || event.type === "agent_end" ||
      (event.type === "message_update" && (
        event.assistantMessageEvent?.type === "text_end"
      ));

    if (isEnd) {
      // Deobfuscate content blocks in the event's message/partial
      // (corrects any partial fakes left from streaming)
      const targets = [
        event.message, event.partial,
        event.assistantMessageEvent?.partial,
        event.assistantMessageEvent?.message,
      ];
      for (const target of targets) {
        if (target?.content && Array.isArray(target.content)) {
          for (const block of target.content) {
            if (block?.type === "text" && typeof block.text === "string") {
              const deob = ob().deobfuscate(block.text);
              if (deob !== block.text) block.text = deob;
            }
          }
        }
      }

      // Audit: use the replacement count accumulated during streaming
      const buf = stream[SHROUD_BUF];
      const streamDeobCount = buf?.deobCount ?? 0;
      if (streamDeobCount > 0 && auditActive) {
        try {
          emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), streamDeobCount);
        } catch { /* best-effort */ }
      }
      // Always dump stats on message_end to capture any counter changes
      dumpStatsFile(obfuscator);

      delete stream[SHROUD_BUF];
    }

    return event;
  };
  api.logger?.info("[shroud] Installed global streaming deobfuscation hook");

  // -----------------------------------------------------------------------
  // 7. Outbound fetch intercept: obfuscate ALL user message content before
  //    it reaches any LLM API. This is the last line of defense — it works
  //    regardless of which hooks fire, which OpenClaw version is running,
  //    and which LLM provider is used (Anthropic, OpenAI, Google, etc.).
  //
  //    Patches globalThis.fetch to inspect outbound POST requests to known
  //    LLM API paths (/messages, /chat/completions). If the request body
  //    contains a messages array with user role content, obfuscate it.
  // -----------------------------------------------------------------------
  const LLM_API_PATHS = [
    "/v1/messages",        // Anthropic
    "/v1/chat/completions", // OpenAI / OpenRouter / compatible
    "/chat/completions",    // OpenAI without /v1
    "/messages",            // Anthropic without /v1
  ];

  const originalFetch = globalThis.fetch;
  if (originalFetch && !((globalThis as any).__shroudFetchPatched)) {
    (globalThis as any).__shroudFetchPatched = true;

    globalThis.fetch = async function shroudFetchInterceptor(
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> {
      // Only intercept POST requests with a body
      if (init?.method?.toUpperCase() !== "POST" || !init?.body) {
        return originalFetch.call(globalThis, input, init);
      }

      // Check if the URL matches an LLM API path
      let url: string;
      try {
        url = typeof input === "string" ? input
          : input instanceof URL ? input.toString()
          : (input as Request).url;
      } catch {
        return originalFetch.call(globalThis, input, init);
      }

      const isLlmApi = LLM_API_PATHS.some((p) => url.includes(p));
      if (!isLlmApi) {
        return originalFetch.call(globalThis, input, init);
      }

      // Parse the body and obfuscate user message content
      try {
        const bodyStr = typeof init.body === "string" ? init.body
          : init.body instanceof ArrayBuffer ? new TextDecoder().decode(init.body)
          : init.body instanceof Uint8Array ? new TextDecoder().decode(init.body)
          : null;

        if (!bodyStr) {
          return originalFetch.call(globalThis, input, init);
        }

        const body = JSON.parse(bodyStr);

        if (!Array.isArray(body.messages)) {
          return originalFetch.call(globalThis, input, init);
        }

        let modified = false;

        // Obfuscate system prompt
        if (typeof body.system === "string") {
          const result = ob().obfuscate(body.system);
          if (result.entities.length > 0) {
            body.system = result.obfuscated;
            modified = true;
          }
        } else if (Array.isArray(body.system)) {
          for (const block of body.system) {
            if (block?.type === "text" && typeof block.text === "string") {
              const result = ob().obfuscate(block.text);
              if (result.entities.length > 0) {
                block.text = result.obfuscated;
                modified = true;
              }
            }
          }
        }

        // Obfuscate ALL messages — user, assistant, tool results, everything.
        // Skip text that's already fully obfuscated (all known real values
        // replaced) to avoid double-obfuscation when before_prompt_build
        // already processed the prompt.
        const allMappings = ob()["_store"]?.allMappings?.() ?? new Map();
        const knownReals = allMappings.size > 0 ? new Set(allMappings.keys()) : null;

        function needsObfuscation(text: string): boolean {
          if (!knownReals || knownReals.size === 0) return true;
          // If text contains any known real value, it needs obfuscation
          for (const real of knownReals) {
            if (text.includes(real)) return true;
          }
          return false;
        }

        function obfuscateText(text: string): { text: string; modified: boolean } {
          if (!needsObfuscation(text)) return { text, modified: false };
          const result = ob().obfuscate(text);
          return result.entities.length > 0
            ? { text: result.obfuscated, modified: true }
            : { text, modified: false };
        }

        for (const msg of body.messages) {
          // Only obfuscate user messages and tool results.
          // Assistant messages contain deobfuscated text (real values restored
          // by streaming deobfuscation) — re-obfuscating them creates a second
          // fake that the LLM echoes back alongside the first.
          if (msg.role === "assistant") continue;

          if (typeof msg.content === "string") {
            const r = obfuscateText(msg.content);
            if (r.modified) { msg.content = r.text; modified = true; }
          } else if (Array.isArray(msg.content)) {
            for (const block of msg.content) {
              if (block?.type === "text" && typeof block.text === "string") {
                const r = obfuscateText(block.text);
                if (r.modified) { block.text = r.text; modified = true; }
              }
            }
          }
        }

        if (modified) {
          const newBody = JSON.stringify(body);
          const newInit = { ...init, body: newBody };
          // Update content-length if present
          if (newInit.headers) {
            const headers = new Headers(newInit.headers as HeadersInit);
            headers.set("content-length", String(new TextEncoder().encode(newBody).length));
            newInit.headers = headers;
          }
          return originalFetch.call(globalThis, input, newInit);
        }
      } catch {
        // JSON parse failed or other error — pass through unmodified
      }

      return originalFetch.call(globalThis, input, init);
    };

    api.logger?.info("[shroud] Installed outbound fetch intercept — PII obfuscated before ALL LLM API calls");
  }
}

