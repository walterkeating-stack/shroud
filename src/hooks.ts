/**
 * OpenClaw lifecycle hooks for the Shroud privacy plugin.
 *
 * Privacy architecture — two directions, one fetch intercept:
 *   Outbound (obfuscation):  globalThis.fetch intercept replaces real PII
 *                            with deterministic fakes before ANY LLM API call.
 *   Inbound (deobfuscation): Same fetch intercept buffers the LLM's SSE
 *                            response per content block, deobfuscates fakes
 *                            back to real values, and returns clean events.
 *                            OpenClaw never sees fakes — all channels, sessions,
 *                            and delivery paths receive real text automatically.
 *
 * Hooks:
 * 1. before_prompt_build   (async) -- pre-seed mapping store for the fetch intercept
 * 2. before_message_write  (SYNC)  -- deobfuscate assistant messages for transcript
 * 3. before_tool_call      (async) -- deobfuscate tool params (+ depth tracking)
 * 4. tool_result_persist   (SYNC)  -- obfuscate tool result message
 * 5. message_sending       (async) -- deobfuscate outbound message content (backup)
 * 6. globalThis.__shroudStreamDeobfuscate -- streaming event deobfuscation hook
 * 7. globalThis.__shroudDeobfuscate       -- channel delivery deobfuscation hook
 * 8. globalThis.fetch intercept           -- obfuscates requests, deobfuscates responses
 */

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Obfuscator } from "./obfuscator.js";
import { ObfuscationResult } from "./types.js";
import { BUILTIN_PATTERNS } from "./detectors/regex.js";
import { STATS_FILE, IS_TEST } from "./config.js";
import { DnsCache } from "./dns-cache.js";
import { InjectionDetector } from "./detectors/injection.js";
import { SecurityEventBus } from "./security-event.js";
import type { SecurityEvent } from "./security-event.js";
import { AgentSessionTracker } from "./agent-session.js";
import { BehaviouralProfiler } from "./profiler.js";
import { BaselineStore } from "./profiler-store.js";
import { scanToolCall } from "./detectors/tool-guard.js";
import { PolicyEngine } from "./policy.js";

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
  function stripSlackLinksForHook(text: string): string {
    text = text.replace(/<mailto:[^|>]+\|([^>]*)>/g, "$1");
    text = text.replace(/<https?:\/\/[^|>]+\|([^>]*)>/g, "$1");
    text = text.replace(/<(https?:\/\/[^>]+)>/g, "$1");
    return text;
  }

  const isFirstLoad = !(globalThis as any).__shroudObfuscator;
  if (!IS_TEST) {
    const g = globalThis as any;
    if (g.__shroudObfuscator) {
      obfuscator = g.__shroudObfuscator;
    } else {
      g.__shroudObfuscator = obfuscator;
    }
    // DNS cache for public URL detection — shared across plugin instances
    if (!g.__shroudDnsCache) {
      const cache = new DnsCache();
      g.__shroudDnsCache = cache;
      // Pre-warm with well-known public domains so first-turn URLs pass through
      // without waiting for async DNS resolution. These domains are guaranteed
      // public — no lookup needed.
      const publicDomains = [
        "youtube.com", "youtu.be", "m.youtube.com",
        "google.com", "google.co.uk", "google.de", "google.fr",
        "github.com", "gitlab.com", "bitbucket.org",
        "stackoverflow.com", "stackexchange.com",
        "wikipedia.org", "wikimedia.org",
        "twitter.com", "x.com",
        "reddit.com",
        "linkedin.com",
        "medium.com",
        "npmjs.com", "www.npmjs.com", "pypi.org", "crates.io",
        "docker.com", "hub.docker.com",
        "microsoft.com", "apple.com",
        "mozilla.org",
        "w3.org",
        "archive.org",
      ];
      for (const d of publicDomains) {
        cache.seed(d, "0.0.0.1", true); // address doesn't matter, isPublic=true
        cache.seed("www." + d, "0.0.0.1", true);
      }
    }
  }

  // All hook closures must use the shared obfuscator, not the local parameter.
  // OpenClaw loads the plugin multiple times; only one instance has the mappings.
  const ob = () => getSharedObfuscator(obfuscator);
  const config = ob().config;
  const auditActive = config.auditEnabled || config.verboseLogging;

  // --- Security extension: injection detection (Track 1) ---
  // Runs parallel to the obfuscation pipeline — never touches entity replacement.
  let injectionDetector: InjectionDetector | null = null;
  let securityBus: SecurityEventBus | null = null;

  if (config.injectionDetection !== "off") {
    securityBus = new SecurityEventBus();
    injectionDetector = new InjectionDetector({
      action: config.injectionDetection,
      disabledSignatures: new Set(config.injectionDisabledSignatures),
      minSeverity: config.injectionMinSeverity,
      scanResponses: config.injectionScanResponses,
    });
    // Share via globalThis for shroud_security tool access
    (globalThis as any).__shroudSecurityBus = securityBus;
  }

  // Per-agent detector cache — avoids recreating for the same agent
  const _agentDetectorCache = new Map<string, InjectionDetector>();

  /** Get the injection detector for the current agent, applying policy overrides. */
  function getDetectorForAgent(): InjectionDetector | null {
    if (!injectionDetector) return null;

    const policyEngine = (globalThis as any).__shroudPolicyEngine as PolicyEngine | undefined;
    if (!policyEngine) return injectionDetector; // no policy engine = use default

    const buildId = agentTracker.getCurrentBuildId();
    if (!buildId) return injectionDetector;

    const agentPolicy = policyEngine.getPolicy(buildId);
    if (!agentPolicy.injectionDetection && !agentPolicy.injectionMinSeverity && !agentPolicy.injectionDisabledSignatures?.length) {
      return injectionDetector; // no overrides = use default
    }

    // Check cache
    const cached = _agentDetectorCache.get(buildId);
    if (cached) return cached;

    // Create agent-specific detector with policy overrides
    const det = new InjectionDetector({
      action: (agentPolicy.injectionDetection as "flag" | "block" | "off") || config.injectionDetection,
      disabledSignatures: new Set([
        ...config.injectionDisabledSignatures,
        ...(agentPolicy.injectionDisabledSignatures || []),
      ]),
      minSeverity: (agentPolicy.injectionMinSeverity as "low" | "medium" | "high") || config.injectionMinSeverity,
      scanResponses: config.injectionScanResponses,
    });

    _agentDetectorCache.set(buildId, det);

    // Listen for policy reloads to clear cache
    const pe = (globalThis as any).__shroudPolicyEngine as PolicyEngine | undefined;
    if (pe && !(globalThis as any).__shroudPolicyCacheWired) {
      (globalThis as any).__shroudPolicyCacheWired = true;
      pe.onReload(() => _agentDetectorCache.clear());
    }

    return det;
  }

  // --- Agent session tracking ---
  // Maps LLM calls to local agent identities. Enables per-agent WAF rules,
  // per-agent behavioural baselines, and enriched security logging.
  const agentTracker = (() => {
    const g = globalThis as any;
    if (!g.__shroudAgentTracker) {
      g.__shroudAgentTracker = new AgentSessionTracker();
    }
    return g.__shroudAgentTracker as AgentSessionTracker;
  })();

  // --- Behavioural profiler (Track 3) ---
  // Per-turn feature extraction, cross-session baseline accumulation,
  // anomaly detection. Fire-and-forget on the hot path.
  let profiler: BehaviouralProfiler | null = null;
  if (config.profilingEnabled) {
    const g = globalThis as any;
    if (!g.__shroudProfiler) {
      const profileDir = config.profilingProfileDir.replace("~", process.env.HOME || "/root");
      const store = new BaselineStore(profileDir);
      g.__shroudProfiler = new BehaviouralProfiler(
        {
          mode: config.profilingMode,
          sigma: config.profilingSigma,
          minBaseline: config.profilingMinBaseline,
          profileDir,
        },
        store,
      );
    }
    profiler = g.__shroudProfiler as BehaviouralProfiler;
  }


  // -----------------------------------------------------------------------
  // 1. before_prompt_build (async): obfuscate user prompt
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any) => {

    // Reset tool depth at the start of each turn — tool calls from the
    // previous turn are complete, so the counter should not carry over.
    if (ob().toolDepth > 0) {
      ob().resetToolDepth();
    }

    // --- Extract agent identity from the prompt context ---
    // event.prompt contains session metadata including channel/conversation labels
    // which identify the agent. Register it here so identity is set BEFORE the
    // fetch intercept fires.
    if (typeof event?.prompt === "string" && event.prompt.length > 10) {
      const session = agentTracker.registerAgent(event.prompt);
      if (profiler) profiler.setAgentBuildId(session.agentBuildId);
    }

    // ── DNS cache warming ──
    // Extract all URLs from the prompt and messages, resolve their FQDNs
    // to determine public vs private. This runs BEFORE obfuscation so
    // the sync pipeline's isDocExample() can check the cache.
    //
    // Slack wraps URLs as <https://url|display> or <https://url>.
    // We must strip this markup BEFORE extracting URLs, otherwise the
    // regex won't match and the DNS cache won't warm for Slack messages.
    const dnsCache: DnsCache | undefined = (globalThis as any).__shroudDnsCache;
    if (dnsCache) {
      const urlRe = /https?:\/\/[^\s<>"')\]]+[^\s<>"')\].,;:!?]/g;
      const allUrls: string[] = [];

      // Strip Slack link markup so URL regex can match cleanly
      function stripSlackForDns(text: string): string {
        text = text.replace(/<mailto:[^|>]+\|([^>]*)>/g, "$1");
        text = text.replace(/<(https?:\/\/[^|>]+)\|[^>]*>/g, "$1");
        text = text.replace(/<(https?:\/\/[^>]+)>/g, "$1");
        return text;
      }

      if (typeof event?.prompt === "string") {
        const cleaned = stripSlackForDns(event.prompt);
        for (const m of cleaned.matchAll(urlRe)) allUrls.push(m[0]);
      }
      if (Array.isArray(event?.messages)) {
        for (const msg of event.messages) {
          const texts: string[] = [];
          if (typeof msg.content === "string") texts.push(msg.content);
          else if (Array.isArray(msg.content)) {
            for (const b of msg.content) {
              if (b?.type === "text" && typeof b.text === "string") texts.push(b.text);
            }
          }
          for (const text of texts) {
            const cleaned = stripSlackForDns(text);
            for (const m of cleaned.matchAll(urlRe)) allUrls.push(m[0]);
          }
        }
      }
      if (allUrls.length > 0) {
        try {
          await dnsCache.warmCache(allUrls);
        } catch {
          // DNS failure is non-fatal — URLs will be obfuscated (safe default)
        }
      }
    }

    let totalEntities = 0;

    // Obfuscate the system prompt
    const prompt = event?.prompt;
    let obfuscatedPrompt: string | undefined;
    if (typeof prompt === "string" && prompt) {
      const cleaned = stripSlackLinksForHook(prompt);
      const result = ob().obfuscate(cleaned);
      if (result.entities.length > 0 || cleaned !== prompt) {
        obfuscatedPrompt = result.entities.length > 0 ? result.obfuscated : cleaned;
        totalEntities += result.entities.length;
      }
    }

    // Pre-create mappings for PII in user messages WITHOUT mutating them.
    // This seeds the mapping store so the fetch intercept's response
    // deobfuscation can replace fakes with the correct real values.
    if (Array.isArray(event?.messages)) {
      for (const msg of event.messages) {
        const texts: string[] = [];
        if (typeof msg.content === "string") texts.push(msg.content);
        else if (Array.isArray(msg.content)) {
          for (const b of msg.content) {
            if (b?.type === "text" && typeof b.text === "string") texts.push(b.text);
          }
        }
        for (const text of texts) {
          const cleaned = stripSlackLinksForHook(text);
          const result = ob().obfuscate(cleaned);
          totalEntities += result.entities.length;
          // Do NOT mutate — just creating mappings in the store
        }
      }
    }

    if (totalEntities === 0) return;

    dumpStatsFile(obfuscator);
    api.logger?.info(
      `[shroud] before_prompt_build: obfuscated ${totalEntities} entities (mappings synced)`,
    );

    return obfuscatedPrompt ? { systemPrompt: obfuscatedPrompt } : undefined;
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
      const _raw = typeof msg.content === "string" ? msg.content :
        Array.isArray(msg.content) ? msg.content.map((b: any) => b?.text || "").join("") : "";
      if (_raw.length < 500) api.logger?.info(`[shroud][raw-assistant] ${_raw}`);

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

    // Block the message tool for send actions. The gateway auto-delivers
    // responses — using the message tool causes duplicate messages (one
    // deobfuscated via streaming, one with fakes from the tool call).
    if (event.toolName === "message") {
      api.logger?.info(`[shroud] message tool call: action=${event.params?.action}`);
      if (event.params?.action === "send") {
        api.logger?.info("[shroud] blocked message tool send (prevents duplicate delivery)");
        return { block: true, blockReason: "Response is delivered automatically. Do not use the message tool to send replies." };
      }
    }


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

    // --- Tool call guard: scan for dangerous commands ---
    if (config.injectionDetection !== "off") {
      const toolResult = scanToolCall(event.toolName ?? "unknown", event.params);
      if (toolResult.events.length > 0 && securityBus) {
        const agentSession = agentTracker.getCurrentSession();
        for (const evt of toolResult.events) {
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          securityBus.emit(evt);
        }
        agentTracker.recordSecurityEvent(toolResult.events.length);

        // Block the tool call if dangerous and action=block
        if (toolResult.shouldBlock && config.injectionDetection === "block") {
          api.logger?.warn(
            `[shroud] BLOCKED dangerous tool call: ${event.toolName} — ${toolResult.events[0].description}`,
          );
          return {
            block: true,
            blockReason: `Shroud security: blocked dangerous ${event.toolName} call �� ${toolResult.events[0].description}`,
          };
        }

        // Flag mode: log but don't block
        if (toolResult.events.some(e => e.severity === "high")) {
          api.logger?.warn(
            `[shroud] DANGEROUS tool call detected (flagged): ${event.toolName} — ${toolResult.events[0].description}`,
          );
        }
      }
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

    // String content — direct deobfuscation.
    // IMPORTANT: Always return { content } even if deobfuscation is a no-op.
    // OpenClaw may pass already-deobfuscated text here (from before_message_write
    // modifying the message in place) while the original delivery payload still
    // has fake text. Returning { content } forces OpenClaw to use our text
    // instead of falling back to the original payload.
    if (typeof event.content === "string") {
      const deobfuscated = ob().deobfuscate(event.content);
      if (deobfuscated !== event.content) {
        api.logger?.info("[shroud] message_sending: deobfuscated outbound message");
        if (auditActive) {
          try {
            const { replacementCount } = ob().deobfuscateWithStats(event.content);
            emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), replacementCount);
          } catch { /* best-effort */ }
        }
        dumpStatsFile(obfuscator);
      }
      // Always return content to override the original payload
      return { content: deobfuscated };
    }

    // Array content (blocks) — walk and deobfuscate all text leaves.
    // Always return content to override the original payload (same reason as above).
    if (Array.isArray(event.content)) {
      const newContent = event.content.map((block: any) => {
        if (block && typeof block === "object") {
          if (typeof block.text === "string") {
            const deob = ob().deobfuscate(block.text);
            if (deob !== block.text) return { ...block, text: deob };
          }
          if (typeof block.content === "string") {
            const deob = ob().deobfuscate(block.content);
            if (deob !== block.content) return { ...block, content: deob };
          }
        }
        return block;
      });
      return { content: newContent };
    }
  });

  // -----------------------------------------------------------------------
  // Tool: shroud-stats — rulebase view with hit counters
  // -----------------------------------------------------------------------
  api.registerTool({
    name: "shroud-stats",
    description: "Show plugin diagnostics: rule status, counters, and configuration summary.",
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
    // Streaming event hook — called by patched EventStream.prototype.push().
    // Text deltas pass through unchanged (deobfuscation happens at the fetch
    // response level via per-block SSE flushing). The message_end handler
    // deobfuscates content blocks as a defense-in-depth measure.
    const isTextDelta = event.type === "text_delta";
    const isMessageUpdateTextDelta = event.type === "message_update" &&
      event.assistantMessageEvent?.type === "text_delta";

    if (isTextDelta || isMessageUpdateTextDelta) {
      // Pass through text_delta events unchanged.
      let buf = stream[SHROUD_BUF];
      if (!buf) { buf = { raw: "", deobCount: 0 }; stream[SHROUD_BUF] = buf; }

      const src = isMessageUpdateTextDelta ? event.assistantMessageEvent : event;
      const chunk = typeof src.delta === "string" ? src.delta
        : typeof src.text === "string" ? src.text : "";
      if (chunk) buf.raw += chunk;
      return event;
    }

    // On message_end/done: deobfuscate content blocks in the final message.
    // This is critical for streaming delivery — OpenClaw uses the content
    // blocks from the done/message_end event as the authoritative text for
    // channel delivery. Text_delta deob is disabled (causes garbled
    // concatenation), but message_end content block deob must remain.
    const isEnd = event.type === "done" || event.type === "message_end" ||
      event.type === "error" || event.type === "agent_end" ||
      (event.type === "message_update" && (
        event.assistantMessageEvent?.type === "text_end"
      ));

    if (isEnd) {
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
              if (deob !== block.text) {
                block.text = deob;
              }
            }
          }
        }
      }

      dumpStatsFile(obfuscator);
      delete stream[SHROUD_BUF];
    }

    return event;
  };

  // -----------------------------------------------------------------------
  // 7. Global deobfuscation hook for channel delivery (defense-in-depth).
  //    Primary deobfuscation happens in the fetch response interceptor (8).
  //    This hook is available for any code that calls
  //    globalThis.__shroudDeobfuscate(text) directly.
  // -----------------------------------------------------------------------
  (globalThis as any).__shroudDeobfuscate = (text: string): string => {
    if (typeof text !== "string") return text;
    return ob().deobfuscate(text);
  };

  // -----------------------------------------------------------------------
  // 8. Fetch intercept — the universal privacy boundary.
  //
  //    REQUEST (obfuscation): Patches globalThis.fetch to intercept outbound
  //    POST requests to LLM API paths (/v1/messages, /chat/completions, etc.).
  //    Obfuscates all message content before it leaves the process.
  //
  //    RESPONSE (deobfuscation): Wraps the LLM's SSE response with a
  //    per-block flushing TransformStream. Text deltas are buffered per
  //    content block. On content_block_stop, the accumulated text is
  //    deobfuscated and flushed — first delta gets the full real text,
  //    subsequent deltas are emptied. Non-PII blocks stream with zero delay.
  //    OpenClaw receives clean events; every channel gets real text.
  // -----------------------------------------------------------------------
  const LLM_API_PATHS = [
    "/v1/messages",             // Anthropic
    "/v1/chat/completions",     // OpenAI / OpenRouter / compatible
    "/chat/completions",        // OpenAI without /v1
    "/messages",                // Anthropic without /v1
    "/responses",               // OpenAI Responses API / Codex
    "/codex/responses",         // OpenAI Codex
    ":streamGenerateContent",   // Google Gemini (v1internal:streamGenerateContent)
    ":generateContent",         // Google Gemini (non-streaming)
    "/v1beta/models/",          // Google AI Studio
    "/v1/models/",              // Google Vertex AI
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

      // Track this LLM call against the current agent session
      const callSession = agentTracker.recordLlmCall();

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



        // Extract model ID for agent tracking
        if (typeof body.model === "string") {
          agentTracker.updateModel(body.model);
        }

        // --- Agent identity from the STABLE system prompt ---
        // Must handle all LLM API formats:
        //   Anthropic:   body.system (string or content block array)
        //   OpenAI/OpenRouter/NIM: body.messages[0] where role === "system"
        //   Google:      body.instructions (string)
        let systemForIdentity: string | null = null;
        if (typeof body.system === "string") {
          systemForIdentity = body.system;
        } else if (Array.isArray(body.system)) {
          systemForIdentity = body.system.map((b: any) => b?.text || "").join("\n");
        } else if (typeof body.instructions === "string") {
          systemForIdentity = body.instructions;
        }
        // OpenAI-compatible: system prompt is first message(s) with role "system"
        if (!systemForIdentity && Array.isArray(body.messages)) {
          const systemMsgs = body.messages
            .filter((m: any) => m?.role === "system")
            .map((m: any) => typeof m.content === "string" ? m.content
              : Array.isArray(m.content) ? m.content.map((c: any) => c?.text || "").join("\n")
              : "")
            .filter((s: string) => s.length > 0);
          if (systemMsgs.length > 0) {
            systemForIdentity = systemMsgs.join("\n");
          }
        }
        if (systemForIdentity && systemForIdentity.length > 10) {
          const session = agentTracker.registerAgent(systemForIdentity);
          if (profiler) profiler.setAgentBuildId(session.agentBuildId);
        }

        // Extract tool inventory from body.tools
        if (Array.isArray(body.tools) && body.tools.length > 0) {
          const toolNames = body.tools
            .map((t: any) => t?.name || t?.function?.name || "")
            .filter((n: string) => n.length > 0);
          if (toolNames.length > 0) {
            agentTracker.updateTools(toolNames);
          }
        }

        // Extract SOUL.md from early messages in body.messages
        // OpenClaw may inject it as assistant or user content, in string or block format.
        // Scan the first 5 messages for identity-bearing content (- Name:, You are, SOUL, etc.)
        if (Array.isArray(body.messages) && body.messages.length > 0) {
          const soulPatterns = /(?:-\s*Name:|[Yy]ou\s+are|SOUL|IDENTITY|personality|role:|purpose:)/;
          for (let mi = 0; mi < Math.min(5, body.messages.length); mi++) {
            const m = body.messages[mi];
            let text = "";
            if (typeof m?.content === "string") {
              text = m.content;
            } else if (Array.isArray(m?.content)) {
              text = m.content.map((b: any) => b?.text || "").join("\n");
            }
            if (text.length > 30 && soulPatterns.test(text)) {
              agentTracker.updateSoul(text);
              break;
            }
          }
        }

        let modified = false;

        // Obfuscate system prompt (Anthropic format)
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

        // --- Canary planting (Track 2) ---
        // Plant canary tokens in system prompts after obfuscation.
        // If the canary appears in any response, injection was successful.
        const canary = ob()["_canary"];
        if (canary && config.canarySystemInjection) {
          if (typeof body.system === "string") {
            body.system = canary.injectSystem(body.system);
            modified = true;
          }
          if (config.canaryBehavioural) {
            if (typeof body.system === "string") {
              const { prompt } = canary.injectBehavioural(body.system);
              body.system = prompt;
            }
          }
        }

        // Obfuscate system instruction (Google format)
        if (body.system_instruction) {
          const si = body.system_instruction;
          if (si.parts && Array.isArray(si.parts)) {
            for (const part of si.parts) {
              if (typeof part.text === "string") {
                const result = ob().obfuscate(part.text);
                if (result.entities.length > 0) { part.text = result.obfuscated; modified = true; }
              }
            }
          }
        }

        // Obfuscate instructions (OpenAI Responses format)
        if (typeof body.instructions === "string") {
          const result = ob().obfuscate(body.instructions);
          if (result.entities.length > 0) { body.instructions = result.obfuscated; modified = true; }
        }

        // Determine message array — Anthropic/OpenAI use "messages", Google uses "contents"
        const messageArray = Array.isArray(body.messages) ? body.messages
          : Array.isArray(body.contents) ? body.contents
          : Array.isArray(body.input) ? body.input  // OpenAI Responses
          : null;

        if (!messageArray) {
          if (modified) {
            const newBody = JSON.stringify(body);
            return originalFetch.call(globalThis, input, { ...init, body: newBody });
          }
          return originalFetch.call(globalThis, input, init);
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

        // Strip Slack mrkdwn link formatting before obfuscation.
        // Slack wraps emails as <mailto:X|DISPLAY> and URLs as <URL|DISPLAY>,
        // splitting PII across tag boundaries. If left in, the obfuscator
        // replaces the plain email but leaves <mailto:real@email|...> intact,
        // leaking real PII to the LLM.
        function stripSlackLinks(text: string): string {
          text = text.replace(/<mailto:[^|>]+\|([^>]*)>/g, "$1");
          text = text.replace(/<https?:\/\/[^|>]+\|([^>]*)>/g, "$1");
          text = text.replace(/<(https?:\/\/[^>]+)>/g, "$1");
          return text;
        }

        function obfuscateText(text: string): { text: string; modified: boolean } {
          // Strip Slack markup first so PII detection works on clean text
          const cleaned = stripSlackLinks(text);
          const textChanged = cleaned !== text;
          // Always run obfuscation — the needsObfuscation check was skipping
          // NEW PII that wasn't in the store (e.g., LLM-generated emails
          // echoed back by the user). Detection must run on every message.
          const result = ob().obfuscate(cleaned);
          return result.entities.length > 0 || textChanged
            ? { text: result.obfuscated, modified: true }
            : { text, modified: false };
        }

        for (const msg of messageArray) {
          // Assistant/model messages may contain deobfuscated text (real PII)
          // from before_message_write. Must re-obfuscate to prevent leaking
          // real values to the LLM in subsequent turns.

          // Anthropic/OpenAI: string content
          if (typeof msg.content === "string") {
            const r = obfuscateText(msg.content);
            if (r.modified) {
              msg.content = r.text; modified = true;
            } else if (msg.role === "assistant" || msg.role === "model") {
              const result = ob().obfuscate(msg.content);
              if (result.entities.length > 0) {
                msg.content = result.obfuscated; modified = true;
              }
            }
          }
          // Anthropic/OpenAI: array content blocks
          else if (Array.isArray(msg.content)) {
            const isAssistant = msg.role === "assistant" || msg.role === "model";
            for (const block of msg.content) {
              if (block?.type === "text" && typeof block.text === "string") {
                const r = obfuscateText(block.text);
                if (r.modified) { block.text = r.text; modified = true; }
                else if (isAssistant) {
                  const result = ob().obfuscate(block.text);
                  if (result.entities.length > 0) {
                    block.text = result.obfuscated; modified = true;
                  }
                }
              }
            }
          }
          // Google: parts array
          if (Array.isArray(msg.parts)) {
            for (const part of msg.parts) {
              if (typeof part.text === "string") {
                const r = obfuscateText(part.text);
                if (r.modified) { part.text = r.text; modified = true; }
              }
            }
          }
          // OpenAI Responses: string input items
          if (typeof msg.text === "string") {
            const r = obfuscateText(msg.text);
            if (r.modified) { msg.text = r.text; modified = true; }
          }
        }

        // --- Security: request-side injection scanning (Track 1) ---
        // Runs AFTER obfuscation, scans the ORIGINAL text (pre-obfuscation)
        // for injection patterns. Does NOT modify the request body.
        const activeDetector = getDetectorForAgent();
        if (activeDetector && securityBus) {
          try {
            // Collect all text from the request for scanning
            const textsToScan: string[] = [];
            if (typeof body.system === "string") textsToScan.push(body.system);
            if (typeof body.instructions === "string") textsToScan.push(body.instructions);
            const scanArray = Array.isArray(body.messages) ? body.messages
              : Array.isArray(body.contents) ? body.contents
              : Array.isArray(body.input) ? body.input : null;
            if (scanArray) {
              for (const msg of scanArray) {
                if (typeof msg.content === "string") textsToScan.push(msg.content);
                else if (Array.isArray(msg.content)) {
                  for (const b of msg.content) {
                    if (b?.type === "text" && typeof b.text === "string") textsToScan.push(b.text);
                  }
                }
                if (Array.isArray(msg.parts)) {
                  for (const p of msg.parts) {
                    if (typeof p.text === "string") textsToScan.push(p.text);
                  }
                }
              }
            }

            const allText = textsToScan.join("\n");
            const events = activeDetector.scanRequest(allText);

            // Enrich events with agent identity
            const agentSession = agentTracker.getCurrentSession();
            for (const evt of events) {
              if (agentSession) {
                evt.agentBuildId = agentSession.agentBuildId;
                evt.agentLabel = agentSession.agentLabel;
                evt.agentSessionId = agentSession.sessionId;
              }
              securityBus.emit(evt);
            }
            if (events.length > 0) {
              agentTracker.recordSecurityEvent(events.length);
            }

            // --- Profiler: extract request-side features ---
            if (profiler) {
              try {
                // Collect entity category counts from the last obfuscation result
                const catCounts: Record<string, number> = {};
                const lastStats = ob().getStats() as Record<string, unknown>;
                if (lastStats.detectionsByCategory && typeof lastStats.detectionsByCategory === "object") {
                  Object.assign(catCounts, lastStats.detectionsByCategory);
                }

                // Count image payloads in the request body
                let imgCount = 0;
                let imgBytes = 0;
                try {
                  const scanArr = Array.isArray(body.messages) ? body.messages
                    : Array.isArray(body.contents) ? body.contents : null;
                  if (scanArr) {
                    for (const msg of scanArr) {
                      if (Array.isArray(msg.content)) {
                        for (const block of msg.content) {
                          // Anthropic: { type: "image", source: { data: "base64..." } }
                          if (block?.type === "image" && block?.source?.data) {
                            imgCount++;
                            imgBytes += Math.ceil(block.source.data.length * 0.75);
                          }
                          // OpenAI: { type: "image_url", image_url: { url: "data:..." } }
                          if (block?.type === "image_url" && block?.image_url?.url?.startsWith("data:")) {
                            imgCount++;
                            const commaIdx = block.image_url.url.indexOf(",");
                            if (commaIdx > 0) {
                              imgBytes += Math.ceil((block.image_url.url.length - commaIdx) * 0.75);
                            }
                          }
                        }
                      }
                      // Google: { parts: [{ inlineData: { data: "base64..." } }] }
                      if (Array.isArray(msg.parts)) {
                        for (const part of msg.parts) {
                          if (part?.inlineData?.data) {
                            imgCount++;
                            imgBytes += Math.ceil(part.inlineData.data.length * 0.75);
                          }
                        }
                      }
                    }
                  }
                } catch { /* best effort */ }

                profiler.extractRequestFeatures(
                  allText,
                  catCounts,
                  undefined,
                  imgCount > 0 ? { count: imgCount, totalBytes: imgBytes } : undefined,
                );
              } catch {
                // Profiling must never break the request pipeline
              }
            }

            // Block if configured and high-severity events detected
            // Block if agent's effective policy says block (per-agent or global)
            const effectiveAction = events.length > 0 ? events[0].action : "flagged";
            if (effectiveAction === "blocked" && events.some(e => e.severity === "high")) {
              return new Response(
                JSON.stringify({
                  error: {
                    type: "security_block",
                    message: "Request blocked by Shroud injection detector",
                    events: events.length,
                  },
                }),
                { status: 403, headers: { "content-type": "application/json" } },
              );
            }
          } catch {
            // Security scanning must never break the request pipeline
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
          return deobfuscateResponse(originalFetch.call(globalThis, input, newInit));
        }
      } catch {
        // JSON parse failed or other error — pass through unmodified
      }

      return deobfuscateResponse(originalFetch.call(globalThis, input, init));
    };

    // ── Response deobfuscation ──────────────────────────────
    // Wraps the LLM response to replace fakes with reals BEFORE
    // OpenClaw processes it. This is the universal deobfuscation
    // point — OpenClaw receives clean text, so ALL channels,
    // sessions, and delivery paths get real values automatically.
    //
    // For streaming (SSE): buffers the response body, deobfuscates
    // all text content, returns a new Response with clean data.
    // For JSON: wraps response.json() to deobfuscate.

    // Accumulate all deobfuscated response text for security scanning
    let responseTextAccum = "";
    // Cache usage from LLM response — extracted from SSE message_start or JSON response
    let responseCacheUsage: { inputTokens: number; outputTokens: number; cacheReadTokens: number; cacheWriteTokens: number } | null = null;

    /** Scan deobfuscated response text for security events. Called per-block. */
    function scanDeobfuscatedBlock(deobbed: string): void {
      responseTextAccum += deobbed;

      // Response-side injection scanning (Track 1)
      const respDetector = getDetectorForAgent();
      if (respDetector && securityBus) {
        try {
          const events = respDetector.scanResponse(deobbed);
          const agentSession = agentTracker.getCurrentSession();
          for (const evt of events) {
            if (agentSession) {
              evt.agentBuildId = agentSession.agentBuildId;
              evt.agentLabel = agentSession.agentLabel;
              evt.agentSessionId = agentSession.sessionId;
            }
            securityBus.emit(evt);
          }
          if (events.length > 0) agentTracker.recordSecurityEvent(events.length);
        } catch { /* never break response pipeline */ }
      }

      // Canary leak detection (Track 2)
      const canary = ob()["_canary"];
      if (canary && securityBus) {
        try {
          const leaks = canary.checkLeakNearMatch(deobbed, config.canaryNearMatchDistance);
          const behLeaks = canary.checkBehaviouralLeak(deobbed);
          const allLeaks = [...leaks, ...behLeaks];
          if (allLeaks.length > 0) {
            const agentSession = agentTracker.getCurrentSession();
            for (const leak of allLeaks) {
              securityBus.emit({
                timestamp: Date.now(),
                eventType: "canary_triggered",
                direction: "response",
                threatClass: "instruction_override" as any,
                signatureId: `canary_${leak.canary.type}_${leak.matchType}`,
                severity: "high",
                matchedText: leak.canary.token.slice(0, 50),
                matchStart: 0,
                matchEnd: 0,
                textLength: deobbed.length,
                action: "flagged",
                description: `Canary ${leak.canary.type} leaked (${leak.matchType}, distance=${leak.distance})`,
                agentBuildId: agentSession?.agentBuildId,
                agentLabel: agentSession?.agentLabel,
                agentSessionId: agentSession?.sessionId,
              });
            }
            agentTracker.recordSecurityEvent(allLeaks.length);
          }
        } catch { /* never break response pipeline */ }
      }
    }

    /** Complete profiler turn with accumulated response text. Called at stream end. */
    function finalizeResponseProfiling(): void {
      if (profiler && responseTextAccum.length > 0) {
        try {
          const fv = profiler.extractResponseFeatures(responseTextAccum, [], responseCacheUsage ?? undefined);
          if (fv) {
            const alerts = profiler.analyzeTurn(fv);
            // Emit anomaly alerts as security events
            if (alerts.length > 0 && securityBus) {
              const agentSession = agentTracker.getCurrentSession();
              for (const alert of alerts) {
                securityBus.emit({
                  timestamp: alert.timestamp,
                  eventType: "anomaly_detected",
                  direction: "response",
                  threatClass: "instruction_override" as any, // closest match
                  signatureId: alert.type,
                  severity: alert.severity === "critical" ? "high" : alert.severity === "warning" ? "medium" : "low",
                  matchedText: alert.description,
                  matchStart: 0,
                  matchEnd: 0,
                  textLength: responseTextAccum.length,
                  action: config.profilingMode === "strict" ? "blocked" : "flagged",
                  description: alert.description,
                  agentBuildId: agentSession?.agentBuildId,
                  agentLabel: agentSession?.agentLabel,
                  agentSessionId: agentSession?.sessionId,
                });
              }
              agentTracker.recordSecurityEvent(alerts.length);
            }
          }
        } catch { /* never break response pipeline */ }
      }
      responseTextAccum = "";
    }

    async function deobfuscateResponse(fetchPromise: Promise<Response>): Promise<Response> {
      const response = await fetchPromise;
      if (!response.ok || !response.body) return response;

      const contentType = response.headers.get("content-type") || "";

      // SSE streaming response — per-block flushing.
      // Non-PII events pass through immediately. Text deltas are buffered
      // per content block. When content_block_stop arrives, the block's
      // accumulated text is deobfuscated and all buffered events for that
      // block are flushed — first delta gets the full deobbed text,
      // subsequent deltas get empty strings. Preserves streaming UX:
      // non-PII blocks stream normally, PII blocks delay by ~0.5-1s.
      if (contentType.includes("text/event-stream")) {
        // Per-block state
        const blockAccum: Map<number, string> = new Map();
        const blockBuffer: Map<number, string[]> = new Map();
        // OpenAI per-choice state
        const choiceAccum: Map<number, string> = new Map();
        const choiceBuffer: Map<number, string[]> = new Map();

        let sseRemainder = "";

        const transform = new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, controller) {
            const text = sseRemainder + new TextDecoder().decode(chunk);
            // SSE events are separated by \n\n
            const parts = text.split("\n\n");
            // Last part may be incomplete — save for next chunk
            sseRemainder = parts.pop() || "";

            for (const part of parts) {
              if (!part.trim()) {
                controller.enqueue(new TextEncoder().encode("\n\n"));
                continue;
              }

              const dataLine = part.split("\n").find((l: string) => l.startsWith("data: "));
              if (!dataLine) {
                controller.enqueue(new TextEncoder().encode(part + "\n\n"));
                continue;
              }

              let json: any;
              try { json = JSON.parse(dataLine.slice(6)); } catch {
                controller.enqueue(new TextEncoder().encode(part + "\n\n"));
                continue;
              }

              // Anthropic text_delta: buffer until block_stop
              if (json.type === "content_block_delta" && json.delta?.type === "text_delta") {
                const idx = json.index ?? 0;
                blockAccum.set(idx, (blockAccum.get(idx) || "") + (json.delta.text || ""));
                if (!blockBuffer.has(idx)) blockBuffer.set(idx, []);
                blockBuffer.get(idx)!.push(part);
                // Don't flush yet — wait for content_block_stop
                continue;
              }

              // Anthropic content_block_stop: flush buffered deltas for this block
              if (json.type === "content_block_stop") {
                const idx = json.index ?? 0;
                const accumulated = blockAccum.get(idx);
                const buffered = blockBuffer.get(idx);
                if (accumulated && buffered && buffered.length > 0) {
                  let deobbed = ob().deobfuscate(accumulated);
                  scanDeobfuscatedBlock(deobbed);
                  // Response-side block: replace content with warning if exfiltration detected
                  if (config.injectionDetection === "block" && securityBus) {
                    const recent = securityBus.getEvents();
                    const blocked = recent.find(e => e.direction === "response" && e.severity === "high" && e.timestamp > Date.now() - 500);
                    if (blocked) deobbed = "[Content blocked by Shroud security: exfiltration pattern detected]";
                  }
                  // First buffered delta gets the full deobbed text
                  let first = true;
                  for (const eventStr of buffered) {
                    const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                    if (dLine) {
                      try {
                        const dJson = JSON.parse(dLine.slice(6));
                        if (dJson.delta?.type === "text_delta") {
                          dJson.delta.text = first ? deobbed : "";
                          first = false;
                          const nonDataLines = eventStr.split("\n").filter((l: string) => !l.startsWith("data: ")).join("\n");
                          const rebuilt = (nonDataLines ? nonDataLines + "\n" : "") + "data: " + JSON.stringify(dJson);
                          controller.enqueue(new TextEncoder().encode(rebuilt + "\n\n"));
                          continue;
                        }
                      } catch {}
                    }
                    controller.enqueue(new TextEncoder().encode(eventStr + "\n\n"));
                  }
                  blockAccum.delete(idx);
                  blockBuffer.delete(idx);
                }
                // Emit the stop event itself
                controller.enqueue(new TextEncoder().encode(part + "\n\n"));
                continue;
              }

              // OpenAI delta.content: buffer until finish_reason
              if (Array.isArray(json.choices)) {
                let buffered = false;
                for (const choice of json.choices) {
                  const idx = choice.index ?? 0;
                  if (typeof choice.delta?.content === "string") {
                    choiceAccum.set(idx, (choiceAccum.get(idx) || "") + choice.delta.content);
                    if (!choiceBuffer.has(idx)) choiceBuffer.set(idx, []);
                    choiceBuffer.get(idx)!.push(part);
                    buffered = true;
                  }
                  // finish_reason signals block complete — flush
                  if (choice.finish_reason) {
                    const accumulated = choiceAccum.get(idx);
                    const buf = choiceBuffer.get(idx);
                    if (accumulated && buf && buf.length > 0) {
                      let deobbed = ob().deobfuscate(accumulated);
                      scanDeobfuscatedBlock(deobbed);
                      if (config.injectionDetection === "block" && securityBus) {
                        const recent = securityBus.getEvents();
                        const blocked = recent.find(e => e.direction === "response" && e.severity === "high" && e.timestamp > Date.now() - 500);
                        if (blocked) deobbed = "[Content blocked by Shroud security: exfiltration pattern detected]";
                      }
                      let first = true;
                      for (const eventStr of buf) {
                        const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                        if (dLine) {
                          try {
                            const dJson = JSON.parse(dLine.slice(6));
                            if (Array.isArray(dJson.choices)) {
                              for (const c of dJson.choices) {
                                if (typeof c.delta?.content === "string") {
                                  c.delta.content = first ? deobbed : "";
                                  first = false;
                                }
                              }
                              const nonDataLines = eventStr.split("\n").filter((l: string) => !l.startsWith("data: ")).join("\n");
                              const rebuilt = (nonDataLines ? nonDataLines + "\n" : "") + "data: " + JSON.stringify(dJson);
                              controller.enqueue(new TextEncoder().encode(rebuilt + "\n\n"));
                              continue;
                            }
                          } catch {}
                        }
                        controller.enqueue(new TextEncoder().encode(eventStr + "\n\n"));
                      }
                      choiceAccum.delete(idx);
                      choiceBuffer.delete(idx);
                    }
                    buffered = false;
                  }
                }
                if (buffered) continue;
              }

              // Extract LLM cache usage from message_start (Anthropic) or stream events (OpenAI)
              const usage = json.message?.usage || json.usage;
              if (usage) {
                responseCacheUsage = {
                  inputTokens: usage.input_tokens || usage.prompt_tokens || 0,
                  outputTokens: usage.output_tokens || usage.completion_tokens || 0,
                  cacheReadTokens: usage.cache_read_input_tokens || usage.prompt_tokens_details?.cached_tokens || 0,
                  cacheWriteTokens: usage.cache_creation_input_tokens || 0,
                };
              }

              // Deobfuscate content blocks in message events (message_start etc)
              if (Array.isArray(json.message?.content)) {
                for (const block of json.message.content) {
                  if (block?.type === "text" && typeof block.text === "string") {
                    block.text = ob().deobfuscate(block.text);
                  }
                }
                const nonDataLines = part.split("\n").filter((l: string) => !l.startsWith("data: ")).join("\n");
                const rebuilt = (nonDataLines ? nonDataLines + "\n" : "") + "data: " + JSON.stringify(json);
                controller.enqueue(new TextEncoder().encode(rebuilt + "\n\n"));
                continue;
              }

              // All other events pass through unchanged
              controller.enqueue(new TextEncoder().encode(part + "\n\n"));
            }
          },

          flush(controller) {
            // Flush any remaining buffered content (stream ended mid-block)
            for (const [idx, buffered] of blockBuffer) {
              const accumulated = blockAccum.get(idx) || "";
              const deobbed = ob().deobfuscate(accumulated);
              scanDeobfuscatedBlock(deobbed);
              let first = true;
              for (const eventStr of buffered) {
                const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                if (dLine) {
                  try {
                    const dJson = JSON.parse(dLine.slice(6));
                    if (dJson.delta?.type === "text_delta") {
                      dJson.delta.text = first ? deobbed : "";
                      first = false;
                      const nonDataLines = eventStr.split("\n").filter((l: string) => !l.startsWith("data: ")).join("\n");
                      const rebuilt = (nonDataLines ? nonDataLines + "\n" : "") + "data: " + JSON.stringify(dJson);
                      controller.enqueue(new TextEncoder().encode(rebuilt + "\n\n"));
                      continue;
                    }
                  } catch {}
                }
                controller.enqueue(new TextEncoder().encode(eventStr + "\n\n"));
              }
            }
            for (const [idx, buffered] of choiceBuffer) {
              const accumulated = choiceAccum.get(idx) || "";
              const deobbed = ob().deobfuscate(accumulated);
              scanDeobfuscatedBlock(deobbed);
              let first = true;
              for (const eventStr of buffered) {
                const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                if (dLine) {
                  try {
                    const dJson = JSON.parse(dLine.slice(6));
                    if (Array.isArray(dJson.choices)) {
                      for (const c of dJson.choices) {
                        if (typeof c.delta?.content === "string") {
                          c.delta.content = first ? deobbed : "";
                          first = false;
                        }
                      }
                      const nonDataLines = eventStr.split("\n").filter((l: string) => !l.startsWith("data: ")).join("\n");
                      const rebuilt = (nonDataLines ? nonDataLines + "\n" : "") + "data: " + JSON.stringify(dJson);
                      controller.enqueue(new TextEncoder().encode(rebuilt + "\n\n"));
                      continue;
                    }
                  } catch {}
                }
                controller.enqueue(new TextEncoder().encode(eventStr + "\n\n"));
              }
            }
            if (sseRemainder.trim()) {
              controller.enqueue(new TextEncoder().encode(sseRemainder));
            }
            // Finalize profiling with accumulated response text
            finalizeResponseProfiling();
          },
        });

        const newBody = response.body.pipeThrough(transform);
        return new Response(newBody, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      }

      // JSON response (non-streaming)
      if (contentType.includes("application/json")) {
        const text = await response.text();
        try {
          const json = JSON.parse(text);
          // Extract cache usage from JSON response
          const jsonUsage = json.usage;
          if (jsonUsage) {
            responseCacheUsage = {
              inputTokens: jsonUsage.input_tokens || jsonUsage.prompt_tokens || 0,
              outputTokens: jsonUsage.output_tokens || jsonUsage.completion_tokens || 0,
              cacheReadTokens: jsonUsage.cache_read_input_tokens || jsonUsage.prompt_tokens_details?.cached_tokens || 0,
              cacheWriteTokens: jsonUsage.cache_creation_input_tokens || 0,
            };
          }
          if (Array.isArray(json.content)) {
            for (const block of json.content) {
              if (block?.type === "text" && typeof block.text === "string") {
                block.text = ob().deobfuscate(block.text);
                scanDeobfuscatedBlock(block.text);
              }
            }
          }
          if (Array.isArray(json.choices)) {
            for (const choice of json.choices) {
              if (typeof choice.message?.content === "string") {
                choice.message.content = ob().deobfuscate(choice.message.content);
                scanDeobfuscatedBlock(choice.message.content);
              }
            }
          }
          finalizeResponseProfiling();
          return new Response(JSON.stringify(json), {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        } catch {
          return new Response(text, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        }
      }

      return response;
    }

  }
}

