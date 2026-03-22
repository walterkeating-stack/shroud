/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Registers 5 hooks:
 * 1. before_prompt_build  (async) -- obfuscate user prompt via prependContext
 * 2. before_llm_send     (async) -- obfuscate LLM input messages + return transformResponse for deobfuscation
 * 3. before_tool_call    (async) -- deobfuscate tool params (+ depth tracking)
 * 4. tool_result_persist  (SYNC) -- obfuscate tool result message
 * 5. message_sending     (async) -- deobfuscate outbound message content (fallback)
 */

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Obfuscator } from "./obfuscator.js";
import { ShroudConfig, ObfuscationResult, ComplianceReport } from "./types.js";
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
): { messages: unknown[]; stats: ObfuscationStats; complianceReport?: ComplianceReport } {
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
  let lastComplianceReport: ComplianceReport | undefined;

  const obfuscatedMessages = messages.map((msg: any) => {
    if (!msg || typeof msg !== "object") return msg;

    if (typeof msg.content === "string") {
      const result = obfuscator.obfuscate(msg.content);
      stats.inputChars += msg.content.length;
      stats.outputChars += result.obfuscated.length;
      if (result.complianceReport) lastComplianceReport = result.complianceReport;
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
          if (result.complianceReport) lastComplianceReport = result.complianceReport;
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

  return { messages: obfuscatedMessages, stats, complianceReport: lastComplianceReport };
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
  complianceReport?: ComplianceReport,
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
    if (complianceReport) {
      obj.compliance = complianceReport;
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
    if (complianceReport && !complianceReport.passed) {
      parts.push(`COMPLIANCE_WARN=missing:[${complianceReport.missing.join(",")}]`);
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
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any) => {
    const prompt = event?.prompt;
    if (typeof prompt !== "string" || !prompt) return;

    const result = obfuscator.obfuscate(prompt);
    if (result.entities.length === 0) return;

    // Feature 4: Compliance warnings
    if (result.complianceReport && !result.complianceReport.passed) {
      api.logger?.warn(
        `[shroud][compliance] Missing locked categories: ${result.complianceReport.missing.join(", ")}`,
      );
    }

    // Feature 5: Exposure alerts
    const alerts = obfuscator.getExposureAlerts();
    for (const alert of alerts) {
      api.logger?.warn(`[shroud][exposure] ${alert.message}`);
    }

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
  // -----------------------------------------------------------------------
  api.on("before_llm_send", async (event: any) => {
    if (!Array.isArray(event?.messages)) return;

    const totalMessages = event.messages.length;
    let obfuscatedMessages: unknown[];
    let requestId = "";

    if (auditActive) {
      requestId = randomBytes(8).toString("hex");

      const { messages: msgs, stats, complianceReport } = obfuscateMessagesWithStats(
        event.messages,
        obfuscator,
        config,
      );
      obfuscatedMessages = msgs;

      // Build concatenated texts for proof hashes
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
          complianceReport,
        );
      } catch {
        // Logging is best-effort
      }

      // Feature 4: Compliance warnings
      if (complianceReport && !complianceReport.passed) {
        api.logger?.warn(
          `[shroud][compliance] Missing locked categories: ${complianceReport.missing.join(", ")}`,
        );
      }

      // Feature 5: Exposure alerts
      const alerts = obfuscator.getExposureAlerts();
      for (const alert of alerts) {
        api.logger?.warn(`[shroud][exposure] ${alert.message}`);
      }
    } else {
      obfuscatedMessages = obfuscateMessages(event.messages, obfuscator);
    }

    dumpStatsFile(obfuscator);
    api.logger?.info("[shroud] before_llm_send: obfuscated messages + installed transformResponse");

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
  // 3. before_tool_call (async): deobfuscate tool params + track depth
  // -----------------------------------------------------------------------
  api.on("before_tool_call", async (event: any) => {
    if (!event?.params || typeof event.params !== "object") return;

    // Feature 3: Tool chain depth tracking
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
  // 4. tool_result_persist (SYNC): obfuscate tool result message
  // -----------------------------------------------------------------------
  api.on("tool_result_persist", (event: any) => {
    if (!event?.message) return;

    // Feature 3: Exit tool depth
    obfuscator.exitToolCall();

    const obfuscated = walkStrings(event.message, (s) => {
      const result = obfuscator.obfuscate(s);
      return result.obfuscated;
    });

    dumpStatsFile(obfuscator);
    return { message: obfuscated };
  });

  // -----------------------------------------------------------------------
  // 5. message_sending (async): deobfuscate outbound message content
  // -----------------------------------------------------------------------
  api.on("message_sending", async (event: any) => {
    if (typeof event?.content !== "string") return;

    const deobfuscated = obfuscator.deobfuscate(event.content);
    if (deobfuscated === event.content) return;

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
        `Provenance: ${stats.provenanceTagging ? "on" : "off"}`,
        `Tenant: ${stats.tenantId || "none"}`,
        `Shared store: ${stats.sharedStorePath ? "yes" : "no"}`,
      ];

      if (stats.lockedCategories.length > 0) {
        lines.push(`Locked categories: ${stats.lockedCategories.join(", ")}`);
      }

      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  });

  // -----------------------------------------------------------------------
  // Tool: shroud-session-export — export mapping table for handoff
  // -----------------------------------------------------------------------
  if (config.sessionHandoff) {
    api.registerTool({
      name: "shroud-session-export",
      description: "Export Shroud mapping table as encrypted blob for session handoff.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      handler: async () => {
        try {
          const blob = obfuscator.exportSession();
          return {
            content: [{ type: "text", text: `Session exported (${blob.length} chars). Pass this to shroud-session-import in the new session:\n\n${blob}` }],
          };
        } catch (e: any) {
          return {
            content: [{ type: "text", text: `Export failed: ${e.message}` }],
          };
        }
      },
    });

    api.registerTool({
      name: "shroud-session-import",
      description: "Import Shroud mapping table from encrypted blob for session continuity.",
      inputSchema: {
        type: "object",
        properties: { blob: { type: "string", description: "Encrypted session blob" } },
        required: ["blob"],
        additionalProperties: false,
      },
      handler: async (input: { blob: string }) => {
        try {
          obfuscator.importSession(input.blob);
          return {
            content: [{ type: "text", text: "Session imported successfully. Deobfuscation will now work for values from the previous session." }],
          };
        } catch (e: any) {
          return {
            content: [{ type: "text", text: `Import failed: ${e.message}` }],
          };
        }
      },
    });
  }
}
