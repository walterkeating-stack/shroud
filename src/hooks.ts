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
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { writeFile, readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Obfuscator } from "./obfuscator.js";
import { ObfuscationResult } from "./types.js";
import { BUILTIN_PATTERNS } from "./detectors/regex.js";
import { STATS_FILE, IS_TEST } from "./config.js";
import { DnsCache } from "./dns-cache.js";
import { InjectionDetector } from "./detectors/injection.js";
import { SecurityEventBus, ThreatClass } from "./security-event.js";
import type { SecurityEvent } from "./security-event.js";
import { AgentSessionTracker, getBehaviorWarmupState, isHeartbeatPrompt, _isValidAgentLabel, normalizeLabel } from "./agent-session.js";
import { BehaviouralProfiler } from "./profiler.js";
import { BaselineStore } from "./profiler-store.js";
import { scanToolCall } from "./detectors/tool-guard.js";
import { extractIntentSignals, checkToolAlignment, checkEgressAttempt, ToolSequenceTracker, buildToolIntentEvent, TOOL_CATEGORIES } from "./detectors/tool-intent.js";
import type { IntentSignals } from "./detectors/tool-intent.js";
import { resolveAgentContract, validateContract } from "./contracts.js";
import { createTurnContext, validateToolResult, checkExfilChain, checkNovelToolUsage } from "./detectors/result-validator.js";
import { HoneypotManager } from "./detectors/honeypot.js";
import { registerPhantomTools } from "./detectors/phantom-tools.js";
import type { TurnContext } from "./detectors/result-validator.js";
import { PolicyEngine } from "./policy.js";
import { AgentRegistry } from "./agent-registry.js";
import * as sigLoaderMod from "./signature-loader.js";
import { DriftDetector, buildDriftEvent, shouldAlertOnDrift } from "./detectors/drift-detector.js";
import { IntentLeaseManager } from "./intent-lease.js";
import { assessTrustZoneContext, checkTrustZoneOverride } from "./detectors/trust-zone-guard.js";
import { ShadowExecutor, buildShadowEvent } from "./shadow-executor.js";
import { CausalCoherenceTracker, buildCoherenceEvent } from "./causal-coherence.js";
import { VectorStore, buildNovelWorkflowEvent, buildUrlCorrelationEvent } from "./vector-store.js";
import { IntentChain, buildDelegationDriftEvent } from "./intent-chain.js";
import { TransformerScorer } from "./transformer/scorer.js";
import type { AttackTrace } from "./transformer/contrastive.js";
import { FieldScopeResolver } from "./field-scope.js";
import { computeAdaptiveThresholds, isSignatureSuppressed } from "./adaptive-thresholds.js";
import { createFeatureCounterRegistry } from "./feature-counters.js";
import { ImmuneResponseEngine } from "./immune-response.js";
import { AdversarialStressTest } from "./red-team.js";

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

/**
 * Scoped variant of walkStrings — only processes string fields where
 * `shouldScan(fieldName)` returns true. When shouldScan always returns true,
 * behavior is identical to walkStrings.
 */
function walkStringsScoped(
  value: unknown,
  fn: (s: string) => string,
  shouldScan: (fieldName: string) => boolean,
  currentField?: string,
): unknown {
  if (typeof value === "string") {
    if (currentField !== undefined && !shouldScan(currentField)) return value;
    return fn(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (typeof item === "object" && item !== null && "text" in item && typeof (item as any).text === "string") {
        if (!shouldScan("text")) return item;
        return { ...item, text: fn((item as any).text) };
      }
      return walkStringsScoped(item, fn, shouldScan);
    });
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string") {
        out[k] = shouldScan(k) ? fn(v) : v;
      } else {
        out[k] = v;
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
  // Field scoping resolver — reconstructed on access to pick up hot-reloaded config.
  let _fieldScopeResolver: FieldScopeResolver | undefined;
  let _fieldScopeConfigRef: unknown;
  function getFieldScopeResolver(): FieldScopeResolver {
    const liveConfig = ob().config.fieldScoping;
    if (_fieldScopeResolver && _fieldScopeConfigRef === liveConfig) return _fieldScopeResolver;
    _fieldScopeResolver = new FieldScopeResolver(liveConfig);
    _fieldScopeConfigRef = liveConfig;
    return _fieldScopeResolver;
  }
  const auditActive = config.auditEnabled || config.verboseLogging;
  const featureRegistry = (globalThis as any).__shroudFeatureRegistry
    || createFeatureCounterRegistry(config);
  (globalThis as any).__shroudFeatureRegistry = featureRegistry;

  function noteFeature(
    featureId: string,
    input: {
      outcome?: "observed" | "suppressed" | "flagged" | "blocked";
      explanation?: string;
      suppressionReason?: string;
      thresholds?: Record<string, unknown>;
      enabled?: boolean;
      agentBuildId?: string;
      agentLabel?: string;
    } = {},
  ): void {
    const currentSession = agentTracker.getCurrentSession();
    featureRegistry.record(featureId, {
      agentBuildId: input.agentBuildId ?? currentSession?.agentBuildId,
      agentLabel: input.agentLabel ?? currentSession?.agentLabel,
      explanation: input.explanation,
      suppressionReason: input.suppressionReason,
      thresholds: input.thresholds,
      enabled: input.enabled,
      outcome: input.outcome,
    });
  }

  // --- Security extension: injection detection (Track 1) ---
  // Runs parallel to the obfuscation pipeline — never touches entity replacement.
  let injectionDetector: InjectionDetector | null = null;
  let securityBus: SecurityEventBus | null = null;

  if (config.injectionDetection !== "off") {
    // Reuse existing bus across plugin reloads — the dashboard holds the
    // original reference, so creating a new bus would orphan events.
    const isNewBus = !(globalThis as any).__shroudSecurityBus;
    securityBus = (globalThis as any).__shroudSecurityBus || new SecurityEventBus(5000, 60_000);
    // Restore recent events from SIEM JSONL log on fresh start (survives gateway restarts)
    if (isNewBus && config.siemJsonlPath && securityBus) {
      const restored = securityBus.loadFromJsonl(config.siemJsonlPath, 7 * 24 * 3_600_000);
      if (restored > 0) {
        try { writeFileSync("/tmp/shroud-event-restore.log",
          `${new Date().toISOString()} restored ${restored} events from ${config.siemJsonlPath}\n`, { flag: "a" }); } catch {}
      }
    }
    injectionDetector = new InjectionDetector({
      action: config.injectionDetection,
      disabledSignatures: new Set(config.injectionDisabledSignatures),
      minSeverity: config.injectionMinSeverity,
      scanResponses: config.injectionScanResponses,
    });
    // Share via globalThis for shroud_security tool access
    (globalThis as any).__shroudSecurityBus = securityBus;

    // --- Hot-refresh external signatures ---
    if ((config.signaturesUrl || config.signaturesFile) && !(globalThis as any).__shroudSigLoader) {
      const loader = new sigLoaderMod.SignatureLoader({
        url: config.signaturesUrl,
        filePath: config.signaturesFile,
        refreshSec: config.signaturesRefreshSec,
        cacheDir: (config.profilingProfileDir || "~/.shroud/profiles").replace("~", process.env.HOME || "/root"),
      });
      loader.onUpdate((compiled) => {
        // Merge external signatures into ALL detectors (base + per-agent cached)
        if (injectionDetector) {
          injectionDetector.loadExternalSignatures(compiled.injection);
        }
        _agentDetectorCache.clear(); // Force per-agent detectors to reload
        (globalThis as any).__shroudExternalSigs = compiled;
      });
      loader.start().catch(() => {}); // fire-and-forget, non-fatal
      (globalThis as any).__shroudSigLoader = loader;
    }

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

  // --- Agent registry (authoritative source of truth) ---
  // Reads ~/.openclaw/openclaw.json for agent inventory + channel bindings.
  // Resolves agent identity from structured signals (Slack channel IDs,
  // WhatsApp numbers, cron agent IDs) instead of regex-parsing prompts.
  const agentRegistry = (() => {
    const g = globalThis as any;
    if (!g.__shroudAgentRegistry) {
      const reg = new AgentRegistry();
      reg.load(); // sync read, ~22KB. Returns false if missing — no regression.
      g.__shroudAgentRegistry = reg;
    }
    return g.__shroudAgentRegistry as AgentRegistry;
  })();

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

  // --- Persistence: flush profiler + agent sessions on shutdown & periodically ---
  const _rawPersistDir = config.profilingProfileDir || "~/.shroud/profiles";
  const _persistDir = _rawPersistDir.startsWith("~")
    ? _rawPersistDir.replace("~", process.env.HOME || "/root")
    : _rawPersistDir;
  const _agentSessionFile = _persistDir + "/agent-sessions.json";

  const _isCleanLabel = (s: { agentLabel: string; llmCallCount: number }): boolean =>
    s.llmCallCount > 0 && s.agentLabel !== "Unknown Agent" &&
    _isValidAgentLabel(s.agentLabel) &&
    s.agentLabel.length < 30 && s.agentLabel.split(/\s+/).length <= 4 &&
    !/@/.test(s.agentLabel) && !/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s.agentLabel) &&
    !/\+\d{5,}/.test(s.agentLabel) &&
    !s.agentLabel.endsWith(":") && !s.agentLabel.includes("(") &&
    !/^(conversation|session|sender|channel|message|rules|metadata)/i.test(s.agentLabel);

  function _flushToDisk(): void {
    try {
      if (profiler) {
        profiler.finalizeSession();
        // BaselineStore.save() schedules via setImmediate which won't
        // run during SIGTERM — flush synchronously to persist baselines.
        profiler.getBaselineStore()?.flushSync();
      }

      // --- Vector store: record completed workflow + persist ---
      if (_vectorStore && _sessionToolSequence.length > 0) {
        const agentSession = agentTracker.getCurrentSession();
        if (agentSession && agentSession.agentLabel !== "Unknown Agent") {
          // Only treat sessions as unhealthy if tool calls were actually BLOCKED.
          // Flagged events (low/medium severity) are normal noise — the baseline
          // should learn from them. Only blocked = confirmed attack.
          const recentEvents = ((globalThis as any).__shroudSecurityBus || securityBus)?.getEvents() as SecurityEvent[] | undefined;
          const hadBlocks = recentEvents?.some((e: SecurityEvent) =>
            e.action === "blocked" &&
            (e.agentBuildId === agentSession.agentBuildId || e.agentSessionId === agentSession.sessionId)
          ) ?? false;
          _vectorStore.recordWorkflow(
            agentSession.agentBuildId,
            agentSession.sessionId,
            _sessionToolSequence,
            _sessionUrls,
            !hadBlocks, // healthy = no BLOCKED events (flagged is fine)
          );

          // Record URL visits for cross-session correlation
          if (config.urlCorrelationEnabled) {
            for (const url of _sessionUrls) {
              const urlIdx = _sessionToolSequence.indexOf("web_fetch") + 1 ||
                _sessionToolSequence.indexOf("fetch") + 1 ||
                _sessionToolSequence.indexOf("browser") + 1;
              const seqAfter = urlIdx > 0 ? _sessionToolSequence.slice(urlIdx) : _sessionToolSequence;
              _vectorStore.recordUrlVisit(url, agentSession.agentBuildId, agentSession.sessionId, seqAfter, hadBlocks);
            }
          }

          // Save transition stats from coherence tracker
          if (_coherenceTracker) {
            _vectorStore.setTransitionStats(agentSession.agentBuildId, _coherenceTracker.getStats());
          }
        }
        _vectorStore.flush();

        // Immune response: decay expired antibodies + persist state
        if (_immuneEngine) {
          _immuneEngine.decayTick();
          _immuneEngine.flush();
        }

        // Trigger transformer retraining if enough new data.
        // Runs async with setImmediate yields so the gateway stays responsive.
        // Fire-and-forget — _flushToDisk is sync, retraining runs in background.
        if (_transformerScorer) {
          const scorer = _transformerScorer;
          const vs = _vectorStore;
          scorer.maybeRetrain(vs).then(result => {
            if (result) {
              api.logger?.info(`[shroud] Transformer retrained: loss=${result.finalLoss.toFixed(4)}, ${result.sequencesUsed} sequences, ${result.durationMs}ms`);
            }
            scorer._saveModel();
          }).catch(() => {});
        }
      }

      const inMemory = agentTracker.getAllSessions().filter(_isCleanLabel);

      // Merge with existing file — don't overwrite agents that aren't in memory
      // (they may not have made calls this session but are still valid)
      let merged = new Map<string, any>();
      try {
        const existing = JSON.parse(readFileSync(_agentSessionFile, "utf-8")) as any[];
        for (const entry of existing) {
          if (entry.agentLabel && _isValidAgentLabel(entry.agentLabel)) {
            merged.set(normalizeLabel(entry.agentLabel), entry);
          }
        }
      } catch { /* file may not exist */ }

      // In-memory sessions merge into on-disk entries.
      // Privacy counters use Math.max to survive process restarts —
      // in-memory starts at 0 after reload, so we must not overwrite
      // higher disk values.
      for (const s of inMemory) {
        const diskEntry = merged.get(normalizeLabel(s.agentLabel));
        const dp = diskEntry?.privacy || {};
        const sp = s.privacy || {};
        const mergedPrivacy = {
          obfuscationCalls: Math.max(dp.obfuscationCalls || 0, sp.obfuscationCalls || 0),
          deobfuscationCalls: Math.max(dp.deobfuscationCalls || 0, sp.deobfuscationCalls || 0),
          entitiesObfuscated: Math.max(dp.entitiesObfuscated || 0, sp.entitiesObfuscated || 0),
          replacementsDeobfuscated: Math.max(dp.replacementsDeobfuscated || 0, sp.replacementsDeobfuscated || 0),
          categoryCounts: { ...(dp.categoryCounts || {}), ...(sp.categoryCounts || {}) },
        };
        merged.set(normalizeLabel(s.agentLabel), {
          agentLabel: s.agentLabel, agentBuildId: s.agentBuildId,
          sessionId: s.sessionId, llmCallCount: s.llmCallCount,
          securityEventCount: s.securityEventCount,
          detectedModel: s.detectedModel,
          channels: s.channels, classification: s.classification,
          toolInventory: s.toolInventory, startedAt: s.startedAt,
          lastCallAt: s.lastCallAt, soulExtract: s.soulExtract,
          behavior: s.behavior, privacy: mergedPrivacy,
        });
      }

      // Merge APP server agent data (NCG etc.)
      try {
        const appSession = JSON.parse(readFileSync("/tmp/shroud-app-sessions.json", "utf-8"));
        if (appSession && appSession.agentLabel) {
          const appKey = normalizeLabel(appSession.agentLabel);
          const existing = merged.get(appKey);
          if (existing) {
            const ep = existing.privacy || {};
            const ap = appSession.privacy || {};
            existing.privacy = {
              obfuscationCalls: Math.max(ep.obfuscationCalls || 0, ap.obfuscationCalls || 0),
              deobfuscationCalls: Math.max(ep.deobfuscationCalls || 0, ap.deobfuscationCalls || 0),
              entitiesObfuscated: Math.max(ep.entitiesObfuscated || 0, ap.entitiesObfuscated || 0),
              replacementsDeobfuscated: Math.max(ep.replacementsDeobfuscated || 0, ap.replacementsDeobfuscated || 0),
              categoryCounts: { ...ep.categoryCounts, ...ap.categoryCounts },
            };
            existing.llmCallCount = Math.max(existing.llmCallCount || 0, appSession.requestCount || 0);
            if (appSession.classification) existing.classification = appSession.classification;
          } else {
            merged.set(appKey, {
              agentLabel: appSession.agentLabel, agentBuildId: appSession.agentBuildId || "",
              sessionId: "", llmCallCount: appSession.requestCount || 0,
              securityEventCount: appSession.securityEvents || 0, detectedModel: "app-server",
              channels: [appSession.channel || "enterprise-agent"],
              classification: appSession.classification || { role: "APP Agent", confidencePct: 100, confidence: "high", colour: "#06b6d4", signals: ["app-server"] },
              toolInventory: [], startedAt: Date.now(), lastCallAt: Date.now(), soulExtract: "",
              behavior: { toolFrequency: {}, totalToolCalls: 0, avgSimilarity: 0, driftCheckCount: 0, recentSimilarities: [], archetype: "Unknown", archetypeConfidence: 0 },
              privacy: appSession.privacy || {},
            });
          }
        }
      } catch { /* APP session file may not exist */ }

      if (merged.size > 0) {
        mkdirSync(_persistDir, { recursive: true });
        writeFileSync(_agentSessionFile, JSON.stringify([...merged.values()], null, 2), "utf-8");
      }
    } catch {}

    // Red team: run adversarial stress test periodically.
    // Placed outside all nested guards so it fires regardless of vectorStore/profiler state.
    try {
      if (_redTeam) {
        const rtAgent = agentTracker.getCurrentSession();
        if (rtAgent && rtAgent.agentBuildId) {
          const lastRunKey = `__shroudRedTeamLastRun_${rtAgent.agentBuildId}`;
          const lastRunCount = (globalThis as any)[lastRunKey] || 0;
          const flushCount = ((globalThis as any).__shroudFlushCount = ((globalThis as any).__shroudFlushCount || 0) + 1);
          if (lastRunCount === 0 || (flushCount - lastRunCount) >= config.redTeamIntervalSessions) {
            (globalThis as any)[lastRunKey] = flushCount;
            const rtBaseline = profiler?.getBaselineStore()?.load(rtAgent.agentBuildId) ?? null;
            const traces = _transformerScorer?._attackTraceStore?.getAll() ?? [];
            const report = _redTeam.runStressTest(
              traces,
              [{ buildId: rtAgent.agentBuildId, label: rtAgent.agentLabel, baseline: rtBaseline, toolProfile: rtBaseline?.toolProfile }],
              config,
              _immuneEngine,
            );
            _redTeam.flush();
            api.logger?.info(`[shroud] Red team: ${report.overallCoverage}% coverage (${report.totalCaught}/${report.totalScenarios} caught, ${report.patchesApplied} patches)`);
          }
        }
      }
    } catch (err: any) {
      api.logger?.warn(`[shroud] Red team error: ${err?.message}`);
    }
  }

  /**
   * Async version of _flushToDisk — used by timer and per-N-calls paths.
   * Does the same work but uses async I/O to avoid blocking the event loop.
   * _flushToDisk (sync) is kept for SIGTERM/SIGINT where async is unsafe.
   */
  async function _flushToDiskAsync(): Promise<void> {
    try {
      if (profiler) {
        profiler.finalizeSession();
        // Ensure baseline writes reach disk — setImmediate from save()
        // may not run before the next flush overwrites dirty state.
        profiler.getBaselineStore()?.flushSync();
      }

      if (_vectorStore && _sessionToolSequence.length > 0) {
        const agentSession = agentTracker.getCurrentSession();
        if (agentSession && agentSession.agentLabel !== "Unknown Agent") {
          const recentEvents = ((globalThis as any).__shroudSecurityBus || securityBus)?.getEvents() as SecurityEvent[] | undefined;
          const hadBlocks = recentEvents?.some((e: SecurityEvent) =>
            e.action === "blocked" &&
            (e.agentBuildId === agentSession.agentBuildId || e.agentSessionId === agentSession.sessionId)
          ) ?? false;
          _vectorStore.recordWorkflow(
            agentSession.agentBuildId, agentSession.sessionId,
            _sessionToolSequence, _sessionUrls, !hadBlocks,
          );

          if (config.urlCorrelationEnabled) {
            for (const url of _sessionUrls) {
              const urlIdx = _sessionToolSequence.indexOf("web_fetch") + 1 ||
                _sessionToolSequence.indexOf("fetch") + 1 ||
                _sessionToolSequence.indexOf("browser") + 1;
              const seqAfter = urlIdx > 0 ? _sessionToolSequence.slice(urlIdx) : _sessionToolSequence;
              _vectorStore.recordUrlVisit(url, agentSession.agentBuildId, agentSession.sessionId, seqAfter, hadBlocks);
            }
          }

          if (_coherenceTracker) {
            _vectorStore.setTransitionStats(agentSession.agentBuildId, _coherenceTracker.getStats());
          }
        }
        await _vectorStore.flushAsync();

        if (_transformerScorer) {
          const scorer = _transformerScorer;
          const vs = _vectorStore;
          scorer.maybeRetrain(vs).then(result => {
            if (result) {
              api.logger?.info(`[shroud] Transformer retrained: loss=${result.finalLoss.toFixed(4)}, ${result.sequencesUsed} sequences, ${result.durationMs}ms`);
            }
            scorer._saveModel();
          }).catch(() => {});
        }
      }

      // BaselineStore flushes itself async via setImmediate (commit 1)

      // Agent sessions — async merge + write
      const inMemory = agentTracker.getAllSessions().filter(_isCleanLabel);
      let merged = new Map<string, any>();
      try {
        const existing = JSON.parse(await readFile(_agentSessionFile, "utf-8")) as any[];
        for (const entry of existing) {
          if (entry.agentLabel && _isValidAgentLabel(entry.agentLabel)) {
            merged.set(normalizeLabel(entry.agentLabel), entry);
          }
        }
      } catch { /* file may not exist */ }

      // Privacy counters use Math.max to survive process restarts
      for (const s of inMemory) {
        const diskEntry = merged.get(normalizeLabel(s.agentLabel));
        const dp = diskEntry?.privacy || {};
        const sp = s.privacy || {};
        const mergedPrivacy = {
          obfuscationCalls: Math.max(dp.obfuscationCalls || 0, sp.obfuscationCalls || 0),
          deobfuscationCalls: Math.max(dp.deobfuscationCalls || 0, sp.deobfuscationCalls || 0),
          entitiesObfuscated: Math.max(dp.entitiesObfuscated || 0, sp.entitiesObfuscated || 0),
          replacementsDeobfuscated: Math.max(dp.replacementsDeobfuscated || 0, sp.replacementsDeobfuscated || 0),
          categoryCounts: { ...(dp.categoryCounts || {}), ...(sp.categoryCounts || {}) },
        };
        merged.set(normalizeLabel(s.agentLabel), {
          agentLabel: s.agentLabel, agentBuildId: s.agentBuildId,
          sessionId: s.sessionId, llmCallCount: s.llmCallCount,
          securityEventCount: s.securityEventCount,
          detectedModel: s.detectedModel,
          channels: s.channels, classification: s.classification,
          toolInventory: s.toolInventory, startedAt: s.startedAt,
          lastCallAt: s.lastCallAt, soulExtract: s.soulExtract,
          behavior: s.behavior, privacy: mergedPrivacy,
        });
      }

      // Merge APP server agent data (NCG etc.) from session file
      try {
        const appSessionRaw = await readFile("/tmp/shroud-app-sessions.json", "utf-8");
        const appSession = JSON.parse(appSessionRaw);
        if (appSession && appSession.agentLabel) {
          const appKey = normalizeLabel(appSession.agentLabel);
          const existing = merged.get(appKey);
          // Merge: keep higher counters (across restarts)
          if (existing) {
            const ep = existing.privacy || {};
            const ap = appSession.privacy || {};
            existing.privacy = {
              obfuscationCalls: Math.max(ep.obfuscationCalls || 0, ap.obfuscationCalls || 0),
              deobfuscationCalls: Math.max(ep.deobfuscationCalls || 0, ap.deobfuscationCalls || 0),
              entitiesObfuscated: Math.max(ep.entitiesObfuscated || 0, ap.entitiesObfuscated || 0),
              replacementsDeobfuscated: Math.max(ep.replacementsDeobfuscated || 0, ap.replacementsDeobfuscated || 0),
              categoryCounts: { ...ep.categoryCounts, ...ap.categoryCounts },
            };
            existing.llmCallCount = Math.max(existing.llmCallCount || 0, appSession.requestCount || 0);
            if (appSession.classification) existing.classification = appSession.classification;
          } else {
            merged.set(appKey, {
              agentLabel: appSession.agentLabel,
              agentBuildId: appSession.agentBuildId || "",
              sessionId: "", llmCallCount: appSession.requestCount || 0,
              securityEventCount: appSession.securityEvents || 0,
              detectedModel: "app-server",
              channels: [appSession.channel || "enterprise-agent"],
              classification: appSession.classification || { role: "APP Agent", confidencePct: 100, confidence: "high", colour: "#06b6d4", signals: ["app-server"] },
              toolInventory: [], startedAt: Date.now(), lastCallAt: Date.now(),
              soulExtract: "", behavior: { toolFrequency: {}, totalToolCalls: 0, avgSimilarity: 0, driftCheckCount: 0, recentSimilarities: [], archetype: "Unknown", archetypeConfidence: 0 },
              privacy: appSession.privacy || {},
            });
          }
        }
      } catch { /* APP session file may not exist */ }

      if (merged.size > 0) {
        await mkdir(_persistDir, { recursive: true });
        await writeFile(_agentSessionFile, JSON.stringify([...merged.values()], null, 2), "utf-8");
      }
    } catch {}

    // Red team: run adversarial stress test periodically.
    // Must be in the async flush (called by timer + every-5-calls), not just sync flush.
    try {
      if (_redTeam) {
        const rtAgent = agentTracker.getCurrentSession();
        if (rtAgent && rtAgent.agentBuildId) {
          const lastRunKey = `__shroudRedTeamLastRun_${rtAgent.agentBuildId}`;
          const lastRunCount = (globalThis as any)[lastRunKey] || 0;
          const flushCount = ((globalThis as any).__shroudFlushCount = ((globalThis as any).__shroudFlushCount || 0) + 1);
          if (lastRunCount === 0 || (flushCount - lastRunCount) >= config.redTeamIntervalSessions) {
            (globalThis as any)[lastRunKey] = flushCount;
            const rtBaseline = profiler?.getBaselineStore()?.load(rtAgent.agentBuildId) ?? null;
            const traces = _transformerScorer?._attackTraceStore?.getAll() ?? [];
            const report = _redTeam.runStressTest(
              traces,
              [{ buildId: rtAgent.agentBuildId, label: rtAgent.agentLabel, baseline: rtBaseline, toolProfile: rtBaseline?.toolProfile }],
              config,
              _immuneEngine,
            );
            _redTeam.flush();
            api.logger?.info(`[shroud] Red team: ${report.overallCoverage}% coverage (${report.totalCaught}/${report.totalScenarios} caught, ${report.patchesApplied} patches)`);
          }
        }
      }
    } catch (err: any) {
      api.logger?.warn(`[shroud] Red team error: ${err?.message}`);
    }
  }

  // Flush on gateway shutdown (sync — SIGTERM/SIGINT must complete before exit)
  if (!(globalThis as any).__shroudShutdownWired) {
    (globalThis as any).__shroudShutdownWired = true;
    process.on("SIGTERM", _flushToDisk);
    process.on("SIGINT", _flushToDisk);
  }

  // Reset in-memory tracker and reload from disk on each plugin init.
  // This clears stale test data and ensures disk is the source of truth.
  agentTracker.reset();

  // Reload persisted agent sessions from disk
  try {
    if (existsSync(_agentSessionFile)) {
      agentTracker.loadFromFile(_agentSessionFile);
    }
  } catch {}

  // Restore obfuscator counters from persisted stats file so deob counts
  // survive process restarts (the stats file is written on every deob event).
  try {
    if (existsSync(STATS_FILE)) {
      const raw = readFileSync(STATS_FILE, "utf-8");
      const persisted = JSON.parse(raw);
      ob().restoreStats(persisted);
    }
  } catch {}

  // Seed archetypes from role classification when behavior data is empty.
  // Real archetypes build from tool call patterns over time; this provides
  // a reasonable default until enough calls accumulate.
  {
    const ROLE_TO_ARCHETYPE: Record<string, string> = {
      "Security Research": "Deep Researcher",
      "DevOps / SRE": "Operator",
      "System Admin": "Operator",
      "Network Engineering": "Operator",
      "Software Engineering": "Builder",
      "Data / Analytics": "Deep Researcher",
      "Customer Support": "Conversationalist",
      "Sales / Outreach": "Conversationalist",
      "Research": "Deep Researcher",
      "Coaching / Training": "Conversationalist",
      "Writing / Content": "Builder",
      "Legal / Compliance": "Deep Researcher",
      "Finance": "Deep Researcher",
      "Healthcare / Therapy": "Conversationalist",
      "Education / Tutoring": "Conversationalist",
      "E-commerce": "Conversationalist",
      "Entertainment / Adult": "Conversationalist",
      "Gaming": "Explorer",
      "Chatbot / Conversational": "Conversationalist",
      "Personal Assistant": "Explorer",
    };
    for (const session of agentTracker.getAllSessions()) {
      if (session.behavior.totalToolCalls > 0) continue;
      const role = session.classification?.role;
      const mapped = role ? ROLE_TO_ARCHETYPE[role] : undefined;
      if (mapped) {
        session.behavior.archetype = mapped;
        session.behavior.archetypeConfidence = Math.min(40, session.classification.confidencePct / 2);
      }
    }
  }

  // Purge stale baseline files from old unstable build ID scheme.
  // Now that build IDs are derived from labels, orphaned files are garbage.
  if (config.profilingEnabled) {
    const profileDir = config.profilingProfileDir.replace("~", process.env.HOME || "/root");
    const purgeStore = new BaselineStore(profileDir);
    const knownIds = new Set(agentTracker.getAllSessions().map(s => s.agentBuildId));
    const purged = purgeStore.purgeStaleBaselines(knownIds);
    if (purged > 0) {
      try { writeFileSync("/tmp/shroud-baseline-purge.log",
        `${new Date().toISOString()}: purged ${purged} stale baseline files\n`, { flag: "a" }); } catch {}
    }
  }

  // Timer-based periodic flush — ensures persistence even if LLM calls are slow
  if (!(globalThis as any).__shroudFlushTimer) {
    (globalThis as any).__shroudFlushTimer = setInterval(() => {
      _flushToDiskAsync().catch(() => {});
    }, 30_000);
    // Unref so the timer doesn't keep the process alive
    (globalThis as any).__shroudFlushTimer.unref();
  }

  // Periodic flush every 5 LLM calls
  let _flushCounter = 0;
  const _origRecordCall = agentTracker.recordLlmCall.bind(agentTracker);
  agentTracker.recordLlmCall = function(): any {
    const result = _origRecordCall();
    if (++_flushCounter % 5 === 0) {
      _flushToDiskAsync().catch(() => {});
      // Check heartbeat health on all agents
      const hbAlerts = agentTracker.checkHeartbeatHealth();
      if (hbAlerts.length > 0 && securityBus) {
        for (const a of hbAlerts) {
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit({
            timestamp: Date.now(),
            eventType: "anomaly_detected",
            direction: "request",
            threatClass: "instruction_override" as any,
            signatureId: `heartbeat_${a.status}`,
            severity: a.status === "dead" ? "high" : "medium",
            matchedText: a.alert,
            matchStart: 0, matchEnd: 0, textLength: 0,
            action: "flagged",
            description: a.alert,
            agentLabel: a.agentLabel,
            channel: "heartbeat",
          });
        }
      }
    }
    return result;
  };

  // Shared call reason — set in before_prompt_build, read in deobfuscateResponse
  let _callReason = "";
  // Tool intent tracking — set in before_prompt_build, checked in before_tool_call
  let _currentIntent: IntentSignals | null = null;
  let _turnContext: TurnContext | null = null;
  const _toolSequence = new ToolSequenceTracker();
  const _intentLease = new IntentLeaseManager();
  (globalThis as any).__shroudIntentLease = _intentLease;
  // Honeypot manager — injects fake secrets as tripwires
  const _honeypot = new HoneypotManager();
  // Semantic drift detector — tracks trajectory vs user intent
  const _driftDetector = config.driftEnabled ? new DriftDetector({
    driftThreshold: config.driftThreshold,
    suddenTurnDelta: config.driftSuddenTurnDelta,
  }) : null;
  if (_driftDetector) (globalThis as any).__shroudDriftDetector = _driftDetector;
  // System prompt fingerprinting — detects hijacking via TF-IDF similarity.
  // Stores per-agent baseline fingerprint; flags drift between turns AND across sessions.
  // Persisted to disk so baselines survive gateway restarts.
  const _promptFingerprintFile = (() => {
    try {
      const dir = (config.profilingProfileDir || "~/.shroud/profiles").replace(/^~/, homedir());
      try { mkdirSync(dir, { recursive: true }); } catch {}
      return `${dir}/prompt-fingerprints.json`;
    } catch { return ""; }
  })();
  const _promptFingerprints: Map<string, { vec: Float64Array; hash: number; firstSeen: number; turnCount: number }> = (() => {
    const map = new Map<string, { vec: Float64Array; hash: number; firstSeen: number; turnCount: number }>();
    if (_promptFingerprintFile) {
      try {
        const data = JSON.parse(readFileSync(_promptFingerprintFile, "utf-8"));
        // Discard baselines older than 6 hours — stale baselines cause false-positive
        // drift events as natural conversation evolution diverges from an old snapshot.
        const MAX_BASELINE_AGE_MS = 6 * 60 * 60 * 1000;
        const now = Date.now();
        for (const [key, val] of Object.entries(data as Record<string, any>)) {
          if (val && Array.isArray(val.vec) && (now - (val.firstSeen || 0)) < MAX_BASELINE_AGE_MS) {
            map.set(key, { vec: new Float64Array(val.vec), hash: val.hash || 0, firstSeen: val.firstSeen || 0, turnCount: val.turnCount || 0 });
          }
        }
      } catch {}
    }
    return map;
  })();
  function _savePromptFingerprints(): void {
    if (!_promptFingerprintFile) return;
    try {
      const obj: Record<string, any> = {};
      for (const [key, val] of _promptFingerprints) {
        obj[key] = { vec: Array.from(val.vec), hash: val.hash, firstSeen: val.firstSeen, turnCount: val.turnCount };
      }
      writeFileSync(_promptFingerprintFile, JSON.stringify(obj));
    } catch {}
  }
  (globalThis as any).__shroudPromptFingerprints = _promptFingerprints;
  // Shadow executor — runs suspicious tool calls against fake sandbox
  const _shadowExecutor = config.shadowExecutionEnabled ? new ShadowExecutor() : null;
  // Causal coherence tracker — monitors result→action pair distances
  const _coherenceTracker = config.coherenceEnabled ? new CausalCoherenceTracker({
    zScoreThreshold: config.coherenceZScore,
    resultLimit: config.coherenceResultLimit,
  }) : null;
  if (_coherenceTracker) (globalThis as any).__shroudCoherenceTracker = _coherenceTracker;
  // Vector store — persisted workflow fingerprints, clustering, URL correlation
  const _vectorStore = config.vectorStoreEnabled
    ? new VectorStore(config.profilingProfileDir, config.vectorStoreMax)
    : null;
  if (_vectorStore) (globalThis as any).__shroudVectorStore = _vectorStore;
  // Intent chain — multi-agent delegation coherence
  const _intentChain = config.intentChainEnabled ? new IntentChain({
    delegationDriftThreshold: config.delegationDriftThreshold,
  }) : null;
  if (_intentChain) (globalThis as any).__shroudIntentChain = _intentChain;
  // Transformer sequence predictor — learned next-tool anomaly detection.
  // Reuse existing scorer across plugin reloads to preserve inference counters.
  // OC loads the plugin once per agent — without reuse, each load creates a
  // fresh scorer and the dashboard only sees the last one's (empty) stats.
  const _transformerScorer: import("./transformer/scorer.js").TransformerScorer | null = (() => {
    if (!config.transformerEnabled || !_vectorStore) return null;
    const existing = (globalThis as any).__shroudTransformerScorer;
    if (existing) return existing;
    const scorer = TransformerScorer.create(config.profilingProfileDir, {
      anomalyThreshold: config.transformerThreshold,
      windowSize: config.transformerWindowSize,
      minSequenceLength: 3,
      minSessionsToTrain: config.transformerMinSessions,
      trainIntervalSessions: config.transformerTrainInterval,
      intentAttentionThreshold: config.transformerIntentAttentionThreshold,
    }, _vectorStore);
    (globalThis as any).__shroudTransformerScorer = scorer;
    return scorer;
  })();
  // Collective immune response — cross-agent attack propagation
  const _immuneEngine: ImmuneResponseEngine | null = (() => {
    if (!config.immuneEnabled) return null;
    const existing = (globalThis as any).__shroudImmuneEngine;
    if (existing) return existing;
    const engine = new ImmuneResponseEngine(config.profilingProfileDir, {
      ttlSec: config.immuneTtlSec,
      sigmaTightenFactor: config.immuneSigmaTightenFactor,
      matchThreshold: config.immuneMatchThreshold,
      maxAntibodies: config.immuneMaxAntibodies,
    });
    (globalThis as any).__shroudImmuneEngine = engine;
    return engine;
  })();
  // Inject immune response sigma overrides into profiler (if both exist)
  if (_immuneEngine && profiler) {
    profiler.sigmaOverrides = _immuneEngine.getSigmaOverrides(config.profilingSigma);
  }
  // Adversarial stress test — automated red team
  const _redTeam: AdversarialStressTest | null = (() => {
    if (!config.redTeamEnabled) return null;
    const existing = (globalThis as any).__shroudRedTeam;
    if (existing) return existing;
    const rt = new AdversarialStressTest(config.profilingProfileDir, {
      maxScenarios: config.redTeamMaxScenarios,
      mutationCount: config.redTeamMutationCount,
    });
    (globalThis as any).__shroudRedTeam = rt;
    return rt;
  })();
  // Session tool sequence accumulator for vector store workflow recording
  let _sessionToolSequence: string[] = [];
  let _sessionUrls: string[] = [];

  // Phantom tools — canary tool definitions that catch injection through action.
  // Only register once per process (the tools persist across plugin reloads).
  if (config.honeypotEnabled && !(globalThis as any).__shroudPhantomToolsRegistered) {
    (globalThis as any).__shroudPhantomToolsRegistered = true;
    noteFeature("phantom_tools", {
      outcome: "observed",
      explanation: "Registered phantom tool canaries in the runtime tool set.",
    });
    registerPhantomTools(api, (event, toolName, params) => {
      noteFeature("phantom_tools", {
        outcome: "blocked",
        explanation: `Phantom tool ${toolName} was invoked: ${event.description}`,
      });
      const agentSession = agentTracker.getCurrentSession();
      event.agentBuildId = agentSession?.agentBuildId;
      event.agentLabel = agentSession?.agentLabel;
      event.agentSessionId = agentSession?.sessionId;
      ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(event);
      agentTracker.recordSecurityEvent(1);
      api.logger?.warn(`[shroud] PHANTOM TOOL TRIPPED: ${toolName} — confirmed injection`);
      // Record attack trace for contrastive learning (Tier 2) + threat labels (Tier 4)
      if (_transformerScorer && _sessionToolSequence.length > 0) {
        const trace: AttackTrace = {
          legitimatePrefix: [..._sessionToolSequence],
          hijackedSuffix: [toolName],
          injectionPoint: _sessionToolSequence.length,
          source: "phantom",
          threatType: "phantom_tool_invocation",
          timestamp: Date.now(),
        };
        _transformerScorer.recordAttackTrace(trace);
        // Extract trapType from signatureId (format: pt_<trapType>)
        const trapType = event.signatureId.replace(/^pt_/, "") || "data_upload";
        _transformerScorer.onPhantomTrigger(trapType, [..._sessionToolSequence, toolName]);
        // Immune response: extract fingerprint + propagate antibodies fleet-wide
        if (_immuneEngine) {
          const fp = _immuneEngine.extractFingerprint(
            trace, agentSession?.agentBuildId || "", agentSession?.agentLabel || "", "phantom",
            event.signatureId, [], [],
          );
          _immuneEngine.propagate(fp);
        }
      }
    });
  }

  // -----------------------------------------------------------------------
  // 1. before_prompt_build (async): obfuscate user prompt
  // -----------------------------------------------------------------------
  api.on("before_prompt_build", async (event: any, ctx?: any) => {

    // Reset tool depth at the start of each turn — tool calls from the
    // previous turn are complete, so the counter should not carry over.
    if (ob().toolDepth > 0) {
      ob().resetToolDepth();
    }

    // --- Extract agent identity ---
    // Tier 0 (definitive): ctx.agentId from OpenClaw hook context (OC 2026.3.22+)
    // Tier 1: Registry signal matching (Slack channel ID, WhatsApp number, cron agent ID)
    // Tier 2: Regex extraction from prompt text (extractLabelStrict)
    // Tier 3: "Unknown Agent" (transient, not persisted)
    const _looksLikeUserMessage = (p: string): boolean =>
      p.length < 200 && !p.includes("\n") && !/[-•]\s*Name:|Conversation info|```/i.test(p);

    if (typeof event?.prompt === "string" && event.prompt.length > 10 && !_looksLikeUserMessage(event.prompt)) {
      // Tier 0: OpenClaw provides agentId directly via hook context
      let resolvedName: string | undefined;
      if (ctx?.agentId) {
        resolvedName = agentRegistry.getCanonicalName(ctx.agentId) || undefined;
        // Store for tool call boundary checks (before_tool_call doesn't get ctx)
        (globalThis as any).__shroudCurrentCtxAgentId = ctx.agentId;
      }
      // Tier 1: Registry signal matching from prompt content
      if (!resolvedName) {
        resolvedName = agentRegistry.resolve(event.prompt) || undefined;
      }
      const session = agentTracker.registerAgent(event.prompt, [], "unknown", true, resolvedName);
      _intentLease.consumeLease(session.agentBuildId, session.agentLabel, ctx?.agentId || resolvedName);

      // Store ctx metadata on the session for enrichment
      // Derive channel from ctx.channelId or ctx.sessionKey
      const ctxChannel = ctx?.channelId
        || (ctx?.sessionKey?.match(/agent:[^:]+:(\w+)/)?.[1] === "main" ? undefined
          : ctx?.sessionKey?.match(/agent:[^:]+:(\w+)/)?.[1]);
      if (ctxChannel && session.agentLabel !== "Unknown Agent") {
        agentTracker.updateChannel(ctxChannel);
      }
      if (ctx?.trigger) {
        _callReason = ctx.trigger === "heartbeat" ? "heartbeat check"
          : ctx.trigger === "cron" ? "cron job"
          : ctx.trigger === "memory" ? "memory operation"
          : ctx.channelId ? `${ctx.channelId} message` : "LLM call";
      }

      // DEBUG: log failed identifications
      if (session.agentLabel === "Claude Code" || session.agentLabel === "Unknown Agent") {
        const msgs = Array.isArray(event?.messages) ? event.messages : [];
        const msg0 = msgs.length > 0 ? JSON.stringify(msgs[0]).slice(0, 300) : "no messages";
        try { writeFileSync("/tmp/shroud-identity-fail.log",
          `LABEL=${session.agentLabel}\nCTX_AGENT=${ctx?.agentId || "null"}\nCTX_SESSION=${ctx?.sessionKey || "null"}\nCTX_CHANNEL=${ctx?.channelId || "null"}\nCTX_TRIGGER=${ctx?.trigger || "null"}\nREGISTRY=${resolvedName || "null"}\nMSG_COUNT=${msgs.length}\nMSG[0]=${msg0}\nPROMPT_FIRST200:\n${event.prompt.slice(0, 200)}\n===END===\n\n`, { flag: "a" }); } catch {}
      }
      if (profiler) profiler.setAgentBuildId(session.agentBuildId);

      // Detect channel + call reason (fallback when ctx not available)
      if (!ctx?.trigger) {
        const detectedCh = agentTracker.updateChannelFromPrompt(event.prompt);
        if (isHeartbeatPrompt(event.prompt)) {
          (globalThis as any).__shroudCurrentHeartbeat = true;
          _callReason = "heartbeat check";
        } else if (detectedCh === "cron") {
          _callReason = "cron job";
        } else if (detectedCh) {
          const msgSnippet = event.prompt.match(/(?:from\s+\w+\s*(?:Keating)?:\s*)(.{1,60})/i);
          _callReason = detectedCh + " message" + (msgSnippet ? ": " + msgSnippet[1].trim() : "");
        } else {
          _callReason = "LLM call";
        }
      } else if (ctx.trigger === "heartbeat") {
        (globalThis as any).__shroudCurrentHeartbeat = true;
      }

      // ── System prompt fingerprinting ──
      // TF-IDF embed the system prompt and compare against baseline for this agent.
      // Detects prompt hijacking: if the system prompt changes unexpectedly between
      // turns, something injected into it or the agent was reconfigured.
      if (_driftDetector && session.agentBuildId && typeof event.prompt === "string" && event.prompt.length > 50) {
        const baseline = profiler?.getBaselineStore().load(session.agentBuildId);
        const warmup = getBehaviorWarmupState(
          session,
          baseline?.sessionCount || 0,
          config.profilingMinBaseline,
        );
        const provider = _driftDetector.getProvider();
        const promptVec = provider.embed(event.prompt);
        const fpKey = session.agentBuildId;
        const existing = _promptFingerprints.get(fpKey);

        if (!existing) {
          noteFeature("prompt_fingerprint", {
            outcome: "observed",
            explanation: `Initialized prompt fingerprint baseline for ${session.agentLabel}.`,
            thresholds: { similarity: 0.85, warmupSessions: config.profilingMinBaseline },
          });
          // First turn for this agent — check against persisted cross-session baseline
          let hash = 0;
          for (let i = 0; i < Math.min(promptVec.length, 16); i++) {
            hash = ((hash << 5) - hash + Math.round(promptVec[i] * 1000)) | 0;
          }
          _promptFingerprints.set(fpKey, { vec: promptVec, hash, firstSeen: Date.now(), turnCount: 1 });
          _savePromptFingerprints();
        } else {
          existing.turnCount++;
          const similarity = provider.similarity(existing.vec, promptVec);

          if (similarity < 0.85 && !warmup.active) {
            // System prompt changed — could be within-session or cross-session drift
            const isFirstTurn = existing.turnCount === 1;
            const severity = similarity < 0.5 ? "high" : "medium";
            const driftType = isFirstTurn ? "cross-session" : "within-session";
            noteFeature("prompt_fingerprint", {
              outcome: "flagged",
              explanation: `Prompt fingerprint ${driftType} drift for ${session.agentLabel}: similarity=${similarity.toFixed(3)}.`,
              thresholds: { similarity: 0.85, observed: similarity },
            });
            if (securityBus) {
              securityBus.emit({
                timestamp: Date.now(),
                eventType: "anomaly_detected",
                direction: "request" as const,
                severity,
                threatClass: "prompt_fingerprint_drift" as any,
                signatureId: "prompt-fingerprint-v1",
                matchedText: "",
                matchStart: 0,
                matchEnd: 0,
                textLength: event.prompt.length,
                action: "flagged" as const,
                description: `System prompt ${driftType} drift: similarity=${similarity.toFixed(3)} for ${session.agentLabel}. Baseline from ${new Date(existing.firstSeen).toISOString()}. May indicate injection or reconfiguration.`,
                agentBuildId: session.agentBuildId,
                agentLabel: session.agentLabel,
                agentSessionId: session.sessionId,
              });
              agentTracker.recordSecurityEvent(1);
            }
            api.logger?.warn(`[shroud] System prompt ${driftType} fingerprint drift: ${session.agentLabel} similarity=${similarity.toFixed(3)}`);
          } else {
            noteFeature("prompt_fingerprint", {
              outcome: warmup.active ? "suppressed" : "observed",
              explanation: `Prompt fingerprint stable for ${session.agentLabel}: similarity=${similarity.toFixed(3)}.`,
              suppressionReason: warmup.active ? "behavioral warmup" : undefined,
              thresholds: { similarity: 0.85, observed: similarity },
            });
          }
        }
      }
    }

    // ── Tool intent extraction ──
    // Extract intent signals from the user's message for tool call alignment checks.
    // The user message is the last item in event.prompt or event.messages.
    if (config.injectionDetection !== "off") {
      const msgs = Array.isArray(event?.messages) ? event.messages : [];
      const lastUserMsg = msgs.length > 0
        ? (() => {
            const last = msgs[msgs.length - 1];
            const content = last?.content;
            return typeof content === "string" ? content
              : Array.isArray(content) ? content.map((b: any) => b?.text || "").join(" ")
              : "";
          })()
        : (typeof event?.prompt === "string" ? event.prompt.slice(0, 500) : "");
      _currentIntent = extractIntentSignals(lastUserMsg);
      // Set drift detector reference from user's message
      if (_driftDetector && lastUserMsg) {
        _driftDetector.setReference(lastUserMsg);
      }
      // Load agent baseline for adaptive result validation
      const agentSession = agentTracker.getCurrentSession();
      const agentBaseline = (profiler && agentSession?.agentBuildId)
        ? profiler.getBaselineStore().load(agentSession.agentBuildId) ?? null
        : null;
      _turnContext = createTurnContext(_currentIntent, agentBaseline);
      _toolSequence.reset(); // Reset sequence tracker for each new turn

      // --- Causal coherence: reset for new turn ---
      if (_coherenceTracker) {
        _coherenceTracker.resetTurn();
        // Load transition stats from vector store for this agent
        if (_vectorStore && agentSession?.agentBuildId) {
          const stats = _vectorStore.getTransitionStats(agentSession.agentBuildId);
          if (Object.keys(stats).length > 0) _coherenceTracker.loadStats(stats);
        }
      }

      // --- Intent chain: consume delegation or create root node ---
      if (_intentChain && agentSession) {
        _intentChain.consumeDelegation(
          agentSession.agentBuildId,
          agentSession.agentLabel,
          agentSession.sessionId,
          lastUserMsg,
        );
      }

      // --- Reset session sequence accumulators ---
      _sessionToolSequence = [];
      _sessionUrls = [];
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
    const _obfCategoryCounts: Record<string, number> = {};

    // Resolve per-agent category exemptions from contract
    const _resolver = getFieldScopeResolver();
    const _currentSession = agentTracker.getCurrentSession();
    const _exemptCats = _resolver.resolveAgentExemptions(
      _currentSession?.agentLabel ?? "Unknown Agent",
      _currentSession?.classification?.role ?? "General Agent",
    );

    // Obfuscate the system prompt
    const prompt = event?.prompt;
    let obfuscatedPrompt: string | undefined;
    if (typeof prompt === "string" && prompt) {
      const cleaned = stripSlackLinksForHook(prompt);
      const result = ob().obfuscate(cleaned, undefined, _exemptCats);
      if (result.entities.length > 0 || cleaned !== prompt) {
        obfuscatedPrompt = result.entities.length > 0 ? result.obfuscated : cleaned;
        totalEntities += result.entities.length;
        for (const e of result.entities) _obfCategoryCounts[e.category] = (_obfCategoryCounts[e.category] || 0) + 1;
      }
    }

    // Obfuscate ALL messages in-place — seeds the mapping store AND mutates
    // the message array so PII is replaced before OpenClaw builds the request.
    // This is critical when the LLM SDK (e.g. OpenAI v6) captures fetch at
    // construction time, bypassing Shroud's globalThis.fetch intercept.
    // The fetch intercept is still the primary path for SDKs that use
    // globalThis.fetch (Anthropic) — double-obfuscation is safe because
    // already-obfuscated text has no detectable PII entities.
    if (Array.isArray(event?.messages)) {
      for (const msg of event.messages) {
        // String content (Anthropic/OpenAI)
        if (typeof msg.content === "string") {
          const cleaned = stripSlackLinksForHook(msg.content);
          const result = ob().obfuscate(cleaned, undefined, _exemptCats);
          totalEntities += result.entities.length;
          for (const e of result.entities) _obfCategoryCounts[e.category] = (_obfCategoryCounts[e.category] || 0) + 1;
          if (result.entities.length > 0 || cleaned !== msg.content) {
            msg.content = result.entities.length > 0 ? result.obfuscated : cleaned;
          }
        }
        // Array content blocks
        else if (Array.isArray(msg.content)) {
          for (const b of msg.content) {
            if (b?.type === "text" && typeof b.text === "string") {
              const cleaned = stripSlackLinksForHook(b.text);
              const result = ob().obfuscate(cleaned, undefined, _exemptCats);
              totalEntities += result.entities.length;
              for (const e of result.entities) _obfCategoryCounts[e.category] = (_obfCategoryCounts[e.category] || 0) + 1;
              if (result.entities.length > 0 || cleaned !== b.text) {
                b.text = result.entities.length > 0 ? result.obfuscated : cleaned;
              }
            }
            // tool_result blocks with string content
            if (typeof b?.content === "string") {
              const cleaned = stripSlackLinksForHook(b.content);
              const result = ob().obfuscate(cleaned, undefined, _exemptCats);
              totalEntities += result.entities.length;
              for (const e of result.entities) _obfCategoryCounts[e.category] = (_obfCategoryCounts[e.category] || 0) + 1;
              if (result.entities.length > 0 || cleaned !== b.content) {
                b.content = result.entities.length > 0 ? result.obfuscated : cleaned;
              }
            }
          }
        }
        // OpenAI tool_calls in assistant messages
        if (Array.isArray(msg.tool_calls)) {
          for (const tc of msg.tool_calls) {
            if (typeof tc.function?.arguments === "string") {
              const result = ob().obfuscate(tc.function.arguments, undefined, _exemptCats);
              totalEntities += result.entities.length;
              for (const e of result.entities) _obfCategoryCounts[e.category] = (_obfCategoryCounts[e.category] || 0) + 1;
              if (result.entities.length > 0) tc.function.arguments = result.obfuscated;
            }
          }
        }
      }
    }

    // Record per-agent obfuscation stats
    if (totalEntities > 0) {
      agentTracker.recordObfuscation(totalEntities, _obfCategoryCounts);
    }

    if (totalEntities === 0 && !config.honeypotEnabled) return;

    // --- Honeypot injection: plant fake secrets as tripwires ---
    if (config.honeypotEnabled && obfuscatedPrompt) {
      const agentSession = agentTracker.getCurrentSession();
      const seed = (agentSession?.agentLabel || "default") + ":" + (agentSession?.sessionId || "0");
      _honeypot.generate(seed, config.secretKey);
      // Register ALL honeypot values with the obfuscator's allowlist so they
      // survive inbound obfuscation (otherwise Shroud neutralizes its own tripwires)
      obfuscator.addRuntimeAllowlist(_honeypot.getTokens().map(t => t.value));

      // Determine agent maturity for rate-tiered arming
      let agentMaturityInfo: import("./detectors/honeypot.js").AgentMaturityInfo | undefined;
      if (agentSession) {
        const baseline = (profiler && agentSession.agentBuildId)
          ? profiler.getBaselineStore().load(agentSession.agentBuildId)
          : null;
        agentMaturityInfo = {
          maturity: baseline?.maturity ?? null,
          securityEventCount: agentSession.securityEventCount || 0,
        };
      }

      // Rate-limited arming decision (deterministic from seed)
      const decision = _honeypot.arm(seed, config.secretKey, config.honeypotRate, agentMaturityInfo);
      _honeypot.buildContextBlock(); // generates fragments based on arming decision

      if (decision.armed && decision.mode === "loud") {
        // Loud tokens: scatter bare values across the prompt
        const fragments = _honeypot.getContextFragments();
        if (fragments.length > 0 && obfuscatedPrompt.length > 100) {
          const lines = obfuscatedPrompt.split("\n");
          const step = Math.max(1, Math.floor(lines.length / (fragments.length + 1)));
          for (let f = 0; f < fragments.length; f++) {
            const insertAt = Math.min((f + 1) * step, lines.length);
            lines.splice(insertAt, 0, fragments[f]);
          }
          obfuscatedPrompt = lines.join("\n");
        }
      }
      // Quiet tokens: already in allowlist, no prompt injection needed.
      // They look like normal Shroud fakes — invisible to the LLM.
    }

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
        const _dbgStoreSize = (ob() as any)._store?.allMappings?.()?.size ?? -1;
        const { text: deobfuscated, replacementCount } = ob().deobfuscateWithStats(msg.content, "before_message_write");
        api.logger?.info(`[shroud][debug-deob] role=assistant store=${_dbgStoreSize} rc=${replacementCount} changed=${deobfuscated !== msg.content} len=${msg.content.length}`);
        if (deobfuscated === msg.content) return;
        api.logger?.info("[shroud] before_message_write: deobfuscated assistant message");
        if (replacementCount > 0) agentTracker.recordDeobfuscation(replacementCount);
        if (auditActive && replacementCount > 0) {
          try { emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), replacementCount); } catch {}
        }
        dumpStatsFile(obfuscator);
        return { message: { ...msg, content: deobfuscated } };
      }
      if (Array.isArray(msg.content)) {
        const _dbgStoreSize2 = (ob() as any)._store?.allMappings?.()?.size ?? -1;
        api.logger?.info(`[shroud][debug-deob] role=assistant ARRAY path blocks=${msg.content.length} store=${_dbgStoreSize2}`);
        let changed = false;
        let _deobCount = 0;
        const newContent = msg.content.map((block: any) => {
          if (block && typeof block === "object") {
            // Handle blocks with .text (text content blocks)
            if (typeof block.text === "string") {
              const { text: deobfuscated, replacementCount: rc } = ob().deobfuscateWithStats(block.text, "before_message_write");
              api.logger?.info(`[shroud][debug-deob] block.text rc=${rc} changed=${deobfuscated !== block.text} len=${block.text.length} sample="${block.text.slice(0,60)}"`);
              if (deobfuscated !== block.text) {
                changed = true;
                _deobCount += rc;
                return { ...block, text: deobfuscated };
              }
            }
            // Handle blocks with .content as string (tool_result blocks)
            if (typeof block.content === "string") {
              const { text: deobfuscated, replacementCount: rc } = ob().deobfuscateWithStats(block.content, "before_message_write");
              if (deobfuscated !== block.content) {
                changed = true;
                _deobCount += rc;
                return { ...block, content: deobfuscated };
              }
            }
            // Handle blocks with .content as array (nested content blocks)
            if (Array.isArray(block.content)) {
              let innerChanged = false;
              const newInner = block.content.map((inner: any) => {
                if (inner && typeof inner === "object" && typeof inner.text === "string") {
                  const { text: deobfuscated, replacementCount: rc } = ob().deobfuscateWithStats(inner.text, "before_message_write");
                  if (deobfuscated !== inner.text) {
                    innerChanged = true;
                    _deobCount += rc;
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
        if (_deobCount > 0) agentTracker.recordDeobfuscation(_deobCount);
        api.logger?.info("[shroud] before_message_write: deobfuscated assistant blocks");
        dumpStatsFile(obfuscator);
        return { message: { ...msg, content: newContent } };
      }
      return;
    }

    // --- Non-assistant messages: OBFUSCATE (real values → fakes) ---

    // --- Security: injection scanning on user/system messages ---
    // The fetch intercept may be bypassed (e.g. OpenClaw uses undici fetch),
    // so scan here in the hook to catch injections before obfuscation.
    {
      const hookDetector = getDetectorForAgent();
      if (hookDetector && securityBus && role === "user") {
        try {
          let textToScan = "";
          if (typeof msg.content === "string") textToScan = msg.content;
          else if (Array.isArray(msg.content)) {
            textToScan = msg.content
              .map((b: any) => b?.type === "text" && typeof b.text === "string" ? b.text : "")
              .join("\n");
          }
          if (textToScan.length > 0) {
            const injEvents = hookDetector.scanRequest(textToScan);
            noteFeature("injection_signatures", {
              outcome: injEvents.length > 0 ? "flagged" : "observed",
              explanation: injEvents.length > 0
                ? `Hook-side request scan matched ${injEvents.length} injection signatures.`
                : "Hook-side request scan found no injection signatures.",
            });
            const agentSession = agentTracker.getCurrentSession();
            for (const evt of injEvents) {
              if (agentSession) {
                evt.agentBuildId = agentSession.agentBuildId;
                evt.agentLabel = agentSession.agentLabel;
                evt.channel = agentSession.channels?.[agentSession.channels.length - 1];
                evt.agentSessionId = agentSession.sessionId;
              }
              ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            }
            if (injEvents.length > 0) {
              agentTracker.recordSecurityEvent(injEvents.length);
            }
          }
        } catch { /* injection scan must not break obfuscation */ }
      }
    }

    if (typeof msg.content === "string") {
      const result = ob().obfuscate(msg.content);
      if (result.entities.length === 0) return;
      const _cats: Record<string, number> = {};
      for (const e of result.entities) _cats[e.category] = (_cats[e.category] || 0) + 1;
      agentTracker.recordObfuscation(result.entities.length, _cats);
      noteFeature("privacy_obfuscation", {
        outcome: "observed",
        explanation: `Obfuscated ${result.entities.length} entities in outbound message content.`,
        thresholds: { categories: _cats },
      });
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
      {
        const _cats: Record<string, number> = {};
        let _totalEnt = 0;
        for (const result of allResults) {
          _totalEnt += result.entities.length;
          for (const e of result.entities) _cats[e.category] = (_cats[e.category] || 0) + 1;
        }
        if (_totalEnt > 0) agentTracker.recordObfuscation(_totalEnt, _cats);
        if (_totalEnt > 0) {
          noteFeature("privacy_obfuscation", {
            outcome: "observed",
            explanation: `Obfuscated ${_totalEnt} entities across structured outbound message blocks.`,
            thresholds: { categories: _cats },
          });
        }
      }
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


    // --- HONEYPOT CHECK (first — 100% certainty, always block) ---
    if (config.honeypotEnabled && _honeypot.getTokens().length > 0) {
      const honeypotHit = _honeypot.checkToolCall(event.toolName ?? "unknown", event.params);
      if (honeypotHit) {
        noteFeature("honeypot", {
          outcome: "blocked",
          explanation: `Honeypot secret used via ${event.toolName ?? "unknown"}: ${honeypotHit.description}`,
        });
        const agentSession = agentTracker.getCurrentSession();
        honeypotHit.agentBuildId = agentSession?.agentBuildId;
        honeypotHit.agentLabel = agentSession?.agentLabel;
        honeypotHit.agentSessionId = agentSession?.sessionId;
        ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(honeypotHit);
        agentTracker.recordSecurityEvent(1);
        api.logger?.warn(`[shroud] HONEYPOT TRIPPED: ${honeypotHit.description}`);
        // Record attack trace for contrastive learning (Tier 2) + threat labels (Tier 4)
        if (_transformerScorer && _sessionToolSequence.length > 0) {
          const trace: AttackTrace = {
            legitimatePrefix: [..._sessionToolSequence],
            hijackedSuffix: [event.toolName ?? "unknown"],
            injectionPoint: _sessionToolSequence.length,
            source: "honeypot",
            threatType: "honeypot_credential",
            timestamp: Date.now(),
          };
          _transformerScorer.recordAttackTrace(trace);
          // Extract token type from signatureId (format: hp_<tokenType>)
          const tokenType = honeypotHit.signatureId.replace(/^hp_/, "") || "credential";
          _transformerScorer.onHoneypotTrigger(
            tokenType,
            [..._sessionToolSequence, event.toolName ?? "unknown"],
            _sessionToolSequence.length,
          );
          // Immune response: extract fingerprint + propagate antibodies fleet-wide
          if (_immuneEngine) {
            const fp = _immuneEngine.extractFingerprint(
              trace, agentSession?.agentBuildId || "", agentSession?.agentLabel || "", "honeypot",
              honeypotHit.signatureId, [], [],
            );
            _immuneEngine.propagate(fp);
          }
        }
        // Always block — honeypot trips are 100% injection, no false positives possible
        return { block: true, blockReason: `Shroud security: honeypot triggered — confirmed injection attempt` };
      } else {
        noteFeature("honeypot", {
          outcome: "observed",
          explanation: `Honeypot check passed for ${event.toolName ?? "unknown"}.`,
        });
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
      noteFeature("tool_guard", {
        outcome: toolResult.shouldBlock && config.injectionDetection === "block"
          ? "blocked"
          : toolResult.events.length > 0 ? "flagged" : "observed",
        explanation: toolResult.events.length > 0
          ? `Tool guard matched ${toolResult.events.length} dangerous-call signatures on ${event.toolName}.`
          : `Tool guard cleared ${event.toolName}.`,
      });
      if (toolResult.events.length > 0 && securityBus) {
        const agentSession = agentTracker.getCurrentSession();
        for (const evt of toolResult.events) {
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.channel = agentSession?.channels?.[agentSession.channels.length - 1];
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
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

      // --- Sandbox boundary check: is this tool outside the agent's configured allowlist? ---
      {
        const currentSession = agentTracker.getCurrentSession();
        const currentContract = currentSession
          ? resolveAgentContract(currentSession.agentLabel, currentSession.classification?.role || "General Agent")
          : null;
        const ctxAgentId = (globalThis as any).__shroudCurrentCtxAgentId;
        const checkAgentId = ctxAgentId || currentSession?.agentLabel;
        if (checkAgentId && agentRegistry.loaded) {
          // Try by agent ID first, then by looking up the agent from registry
          const agentId = agentRegistry.getAgent(ctxAgentId)
            ? ctxAgentId
            : (() => { for (const a of agentRegistry.getAllAgents()) { if (a.canonicalName === currentSession?.agentLabel) return a.id; } return null; })();
          if (agentId) {
            const violation = agentRegistry.checkToolBoundary(agentId, event.toolName ?? "");
            if (violation) {
              noteFeature("sandbox_boundary", {
                outcome: config.injectionDetection === "block" ? "blocked" : "flagged",
                explanation: violation,
              });
              const evt: any = {
                timestamp: Date.now(),
                eventType: "anomaly_detected",
                direction: "request",
                threatClass: "privilege_escalation",
                signatureId: "sb_tool_boundary",
                severity: "high" as const,
                matchedText: `${event.toolName}: ${violation}`,
                matchStart: 0, matchEnd: 0, textLength: 0,
                action: config.injectionDetection === "block" ? "blocked" : "flagged",
                description: violation,
                agentBuildId: currentSession?.agentBuildId,
                agentLabel: currentSession?.agentLabel,
                agentSessionId: currentSession?.sessionId,
              };
              ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
              agentTracker.recordSecurityEvent(1);

              if (config.injectionDetection === "block") {
                api.logger?.warn(`[shroud] BLOCKED sandbox boundary violation: ${violation}`);
                return { block: true, blockReason: `Shroud security: ${violation}` };
              }
              api.logger?.warn(`[shroud] Sandbox boundary violation (flagged): ${violation}`);
            } else {
              noteFeature("sandbox_boundary", {
                outcome: "observed",
                explanation: `Sandbox boundary allowed ${event.toolName ?? "unknown"} for ${currentSession?.agentLabel || agentId}.`,
              });
            }
          }
        }

        if (currentSession && currentContract) {
          const contractViolation = validateContract(
            currentContract,
            event.toolName ?? "unknown",
            event.params,
            currentSession.channels || [],
            _currentIntent?.mentionedDomains || new Set<string>(),
          );
          if (contractViolation) {
            noteFeature("contract_enforcement", {
              outcome: config.injectionDetection === "block" && contractViolation.severity === "high" ? "blocked" : "flagged",
              explanation: contractViolation.reason,
            });
            const evt: any = {
              timestamp: Date.now(),
              eventType: "anomaly_detected",
              direction: "request",
              threatClass: "privilege_escalation",
              signatureId: contractViolation.signatureId,
              severity: contractViolation.severity,
              matchedText: `${event.toolName}: ${contractViolation.reason}`,
              matchStart: 0, matchEnd: 0, textLength: 0,
              action: config.injectionDetection === "block" ? "blocked" : "flagged",
              description: contractViolation.reason,
              agentBuildId: currentSession.agentBuildId,
              agentLabel: currentSession.agentLabel,
              agentSessionId: currentSession.sessionId,
            };
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block" && contractViolation.severity === "high") {
              api.logger?.warn(`[shroud] BLOCKED contract violation: ${contractViolation.reason}`);
              return { block: true, blockReason: `Shroud security: ${contractViolation.reason}` };
            }
            api.logger?.warn(`[shroud] Contract violation (flagged): ${contractViolation.reason}`);
          } else {
            noteFeature("contract_enforcement", {
              outcome: "observed",
              explanation: `Capability contract allowed ${event.toolName ?? "unknown"} for ${currentSession.agentLabel}.`,
            });
          }

          const leaseViolation = _intentLease.checkLease(currentSession.agentBuildId, event.toolName ?? "unknown");
          if (leaseViolation) {
            noteFeature("intent_lease", {
              outcome: config.injectionDetection === "block" && leaseViolation.severity === "high" ? "blocked" : "flagged",
              explanation: leaseViolation.reason,
            });
            const evt: any = {
              timestamp: Date.now(),
              eventType: "anomaly_detected",
              direction: "request",
              threatClass: "delegation_drift",
              signatureId: leaseViolation.signatureId,
              severity: leaseViolation.severity,
              matchedText: `${event.toolName}: ${leaseViolation.reason}`,
              matchStart: 0, matchEnd: 0, textLength: 0,
              action: config.injectionDetection === "block" ? "blocked" : "flagged",
              description: leaseViolation.reason,
              agentBuildId: currentSession.agentBuildId,
              agentLabel: currentSession.agentLabel,
              agentSessionId: currentSession.sessionId,
            };
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block" && leaseViolation.severity === "high") {
              api.logger?.warn(`[shroud] BLOCKED intent lease violation: ${leaseViolation.reason}`);
              return { block: true, blockReason: `Shroud security: ${leaseViolation.reason}` };
            }
            api.logger?.warn(`[shroud] Intent lease violation (flagged): ${leaseViolation.reason}`);
          } else {
            noteFeature("intent_lease", {
              outcome: "observed",
              explanation: `Intent lease allowed ${event.toolName ?? "unknown"} for delegated agent ${currentSession.agentLabel}.`,
            });
          }

          const trustZoneSignal = assessTrustZoneContext(event.toolName ?? "unknown", event.params);
          const trustZoneViolation = trustZoneSignal.risky
            ? checkTrustZoneOverride(event.toolName ?? "unknown", event.params)
            : null;
          if (trustZoneViolation) {
            noteFeature("trust_zone_guard", {
              outcome: config.injectionDetection === "block" ? "blocked" : "flagged",
              explanation: trustZoneViolation.reason,
            });
            const evt: any = {
              timestamp: Date.now(),
              eventType: "anomaly_detected",
              direction: "request",
              threatClass: trustZoneViolation.threatClass,
              signatureId: trustZoneViolation.signatureId,
              severity: trustZoneViolation.severity,
              matchedText: `${event.toolName}: ${trustZoneViolation.reason}`,
              matchStart: 0, matchEnd: 0, textLength: 0,
              action: config.injectionDetection === "block" ? "blocked" : "flagged",
              description: trustZoneViolation.reason,
              agentBuildId: currentSession.agentBuildId,
              agentLabel: currentSession.agentLabel,
              agentSessionId: currentSession.sessionId,
            };
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block") {
              api.logger?.warn(`[shroud] BLOCKED trust-zone override: ${trustZoneViolation.reason}`);
              return { block: true, blockReason: `Shroud security: ${trustZoneViolation.reason}` };
            }
            api.logger?.warn(`[shroud] Trust-zone override (flagged): ${trustZoneViolation.reason}`);
          } else {
            noteFeature("trust_zone_guard", {
              outcome: "observed",
              explanation: `Trust-zone guard cleared ${event.toolName ?? "unknown"}.`,
            });
          }
        }
      }

      // --- Tool intent alignment: does this tool match the user's intent? ---
      if (_currentIntent) {
        const toolName = event.toolName ?? "unknown";

        // 1. Check alignment
        const alignment = checkToolAlignment(toolName, _currentIntent);
        if (!alignment.aligned) {
          noteFeature("tool_alignment", {
            outcome: config.injectionDetection === "block" && alignment.severity === "high" ? "blocked" : "flagged",
            explanation: alignment.reason,
          });
          const evt = buildToolIntentEvent(toolName, alignment, config.injectionDetection === "block" ? "blocked" : "flagged");
          const agentSession = agentTracker.getCurrentSession();
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
          agentTracker.recordSecurityEvent(1);

          if (config.injectionDetection === "block" && alignment.severity === "high") {
            api.logger?.warn(`[shroud] BLOCKED tool intent mismatch: ${alignment.reason}`);
            return { block: true, blockReason: `Shroud security: ${alignment.reason}` };
          }
          api.logger?.info(`[shroud] Tool intent mismatch (flagged): ${alignment.reason}`);
        } else {
          noteFeature("tool_alignment", {
            outcome: "observed",
            explanation: `Tool ${toolName} matched the extracted user intent.`,
          });
        }

        // 2. Check egress attempt
        const egress = checkEgressAttempt(toolName, event.params, _currentIntent);
        if (egress && !egress.aligned) {
          noteFeature("egress_attempt", {
            outcome: config.injectionDetection === "block" && egress.severity === "high" ? "blocked" : "flagged",
            explanation: egress.reason,
          });
          const evt = buildToolIntentEvent(toolName, egress, config.injectionDetection === "block" ? "blocked" : "flagged");
          const agentSession = agentTracker.getCurrentSession();
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
          agentTracker.recordSecurityEvent(1);

          if (config.injectionDetection === "block" && egress.severity === "high") {
            api.logger?.warn(`[shroud] BLOCKED egress attempt: ${egress.reason}`);
            return { block: true, blockReason: `Shroud security: ${egress.reason}` };
          }
          api.logger?.info(`[shroud] Egress attempt (flagged): ${egress.reason}`);
        } else {
          noteFeature("egress_attempt", {
            outcome: "observed",
            explanation: `No suspicious egress intent detected for ${toolName}.`,
          });
        }

        // 3. Track sequence and check for anomalies
        _toolSequence.record(toolName);
        const anomaly = _toolSequence.checkAnomaly();
        if (anomaly) {
          noteFeature("tool_sequence", {
            outcome: "flagged",
            explanation: anomaly.reason,
          });
          const evt = buildToolIntentEvent(toolName, anomaly, "flagged");
          const agentSession = agentTracker.getCurrentSession();
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
          agentTracker.recordSecurityEvent(1);
          api.logger?.warn(`[shroud] Tool sequence anomaly: ${anomaly.reason}`);
        } else {
          noteFeature("tool_sequence", {
            outcome: "observed",
            explanation: `Tool sequence remained consistent through ${toolName}.`,
          });
        }

        // 4. Exfil chain check: communication/network after PII-containing results
        if (_turnContext) {
          const exfil = checkExfilChain(_turnContext, toolName);
          if (exfil) {
            noteFeature("exfil_chain", {
              outcome: config.injectionDetection === "block" ? "blocked" : "flagged",
              explanation: exfil.description,
            });
            const agentSession = agentTracker.getCurrentSession();
            exfil.agentBuildId = agentSession?.agentBuildId;
            exfil.agentLabel = agentSession?.agentLabel;
            exfil.agentSessionId = agentSession?.sessionId;
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(exfil);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block") {
              api.logger?.warn(`[shroud] BLOCKED exfil chain: ${exfil.description}`);
              return { block: true, blockReason: `Shroud security: ${exfil.description}` };
            }
            api.logger?.warn(`[shroud] Exfil chain detected (flagged): ${exfil.description}`);
          } else {
            noteFeature("exfil_chain", {
              outcome: "observed",
              explanation: `No exfiltration chain detected for ${toolName}.`,
            });
          }

          // 5. Novel egress tool check: agent using communication/network tool for the first time
          const novelTool = checkNovelToolUsage(_turnContext, toolName);
          if (novelTool) {
            noteFeature("novel_egress", {
              outcome: config.injectionDetection === "block" ? "blocked" : "flagged",
              explanation: novelTool.description,
            });
            const agentSession = agentTracker.getCurrentSession();
            novelTool.agentBuildId = agentSession?.agentBuildId;
            novelTool.agentLabel = agentSession?.agentLabel;
            novelTool.agentSessionId = agentSession?.sessionId;
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(novelTool);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block") {
              api.logger?.warn(`[shroud] BLOCKED novel egress tool: ${novelTool.description}`);
              return { block: true, blockReason: `Shroud security: ${novelTool.description}` };
            }
            api.logger?.warn(`[shroud] Novel egress tool (flagged): ${novelTool.description}`);
          } else {
            noteFeature("novel_egress", {
              outcome: "observed",
              explanation: `No novel egress behavior for ${toolName}.`,
            });
          }

          // Stash pending tool call for result validation in tool_result_persist
          _turnContext.pendingToolCall = {
            toolName,
            category: TOOL_CATEGORIES[toolName],
            timestamp: Date.now(),
          };
        }
      }

      // --- Behavioral archetype tracking (always, even without drift) ---
      if (!_driftDetector) {
        agentTracker.recordToolCall(event.toolName ?? "unknown");
      }

      // --- Adaptive thresholds: compute per-agent adjustments from profiler baselines ---
      const _agentSession = agentTracker.getCurrentSession();
      const _agentBaseline = _agentSession?.agentBuildId && profiler
        ? profiler.getBaselineStore().load(_agentSession.agentBuildId)
        : null;
      let _adaptiveThresholds = computeAdaptiveThresholds(_agentBaseline, config);
      // Apply immune response overrides — tighten thresholds + force-enable signatures
      if (_immuneEngine) {
        _adaptiveThresholds = _immuneEngine.applyToThresholds(_adaptiveThresholds);
      }
      const _behaviorWarmup = getBehaviorWarmupState(
        _agentSession,
        _agentBaseline?.sessionCount || 0,
        config.profilingMinBaseline,
      );

      // --- Immune response: check session against active antibodies ---
      if (_immuneEngine && _sessionToolSequence.length >= 2) {
        const abMatches = _immuneEngine.matchAntibodies(_sessionToolSequence);
        if (abMatches.length > 0) {
          const best = abMatches[0];
          noteFeature("immune_response", {
            outcome: "flagged",
            explanation: `Session matches antibody ${best.fingerprintId} (similarity=${best.similarity.toFixed(3)})`,
          });
          const immuneEvt: SecurityEvent = {
            timestamp: Date.now(),
            eventType: "anomaly_detected",
            direction: "request",
            threatClass: ThreatClass.IMMUNE_RESPONSE,
            signatureId: `immune_${best.fingerprintId}`,
            severity: best.similarity > 0.9 ? "high" : "medium",
            matchedText: `antibody:${best.fingerprintId}`,
            matchStart: 0,
            matchEnd: 0,
            textLength: 0,
            action: config.injectionDetection === "block" ? "blocked" : "flagged",
            description: `Collective immune response: session tool sequence matches known attack pattern (antibody ${best.fingerprintId}, similarity ${best.similarity.toFixed(3)})`,
            agentBuildId: _agentSession?.agentBuildId,
            agentLabel: _agentSession?.agentLabel,
            agentSessionId: _agentSession?.sessionId,
          };
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(immuneEvt);
          // Re-confirm the antibody to extend TTL
          _immuneEngine.reconfirm(best.fingerprintId);
          // Update sigma overrides for profiler since antibody was confirmed
          if (profiler) {
            profiler.sigmaOverrides = _immuneEngine.getSigmaOverrides(config.profilingSigma);
          }
        }
      }

      // --- Semantic drift detection + behavioral archetype tracking ---
      if (_driftDetector && _currentIntent) {
        const drift = _driftDetector.checkDrift(event.toolName ?? "unknown", event.params);
        // Record tool call for per-agent behavioral archetype mapping
        agentTracker.recordToolCall(event.toolName ?? "unknown", drift.similarity);
        // Use adaptive drift threshold: only flag if similarity is below the per-agent threshold
        const effectiveDrifted = drift.similarity < _adaptiveThresholds.driftThreshold;
        const driftSignature = drift.suddenTurn ? "drift_sudden_turn" : "semantic_drift";
        const shouldAlert = shouldAlertOnDrift(
          event.toolName ?? "unknown",
          { ...drift, drifted: effectiveDrifted },
          _driftDetector.getTrajectory().length,
        );
        if (_behaviorWarmup.active) {
          noteFeature("semantic_drift", {
            outcome: "suppressed",
            explanation: drift.reason || `Semantic drift evaluated for ${event.toolName ?? "unknown"}.`,
            suppressionReason: "behavioral warmup",
            thresholds: { similarity: drift.similarity, threshold: _adaptiveThresholds.driftThreshold },
          });
        } else if ((effectiveDrifted || drift.suddenTurn) && !shouldAlert) {
          noteFeature("semantic_drift", {
            outcome: "suppressed",
            explanation: drift.reason,
            suppressionReason: "routine tool suppression",
            thresholds: { similarity: drift.similarity, threshold: _adaptiveThresholds.driftThreshold },
          });
        } else if ((effectiveDrifted || drift.suddenTurn) && isSignatureSuppressed(driftSignature, _adaptiveThresholds)) {
          noteFeature("semantic_drift", {
            outcome: "suppressed",
            explanation: drift.reason,
            suppressionReason: "adaptive signature suppression",
            thresholds: { similarity: drift.similarity, threshold: _adaptiveThresholds.driftThreshold },
          });
        }
        if (!_behaviorWarmup.active
            && (effectiveDrifted || drift.suddenTurn)
            && shouldAlert
            && !isSignatureSuppressed(driftSignature, _adaptiveThresholds)) {
          noteFeature("semantic_drift", {
            outcome: config.injectionDetection === "block" && drift.severity === "high" ? "blocked" : "flagged",
            explanation: drift.reason,
            thresholds: { similarity: drift.similarity, threshold: _adaptiveThresholds.driftThreshold },
          });
          const evt = buildDriftEvent(event.toolName ?? "unknown", drift,
            config.injectionDetection === "block" ? "blocked" : "flagged");
          const agentSession = agentTracker.getCurrentSession();
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
          agentTracker.recordSecurityEvent(1);

          if (config.injectionDetection === "block" && drift.severity === "high") {
            api.logger?.warn(`[shroud] BLOCKED semantic drift: ${drift.reason}`);
            return { block: true, blockReason: `Shroud security: ${drift.reason}` };
          }
          api.logger?.info(`[shroud] Semantic drift (flagged): ${drift.reason}`);
        } else if (!_behaviorWarmup.active) {
          noteFeature("semantic_drift", {
            outcome: "observed",
            explanation: `Semantic drift within threshold for ${event.toolName ?? "unknown"} (${drift.similarity.toFixed(3)}).`,
            thresholds: { similarity: drift.similarity, threshold: _adaptiveThresholds.driftThreshold },
          });
        }
      }

      // --- Causal coherence: check result→action pair distance ---
      if (_coherenceTracker && _currentIntent) {
        const coherence = _coherenceTracker.checkCoherence(event.toolName ?? "unknown", event.params);
        if (_behaviorWarmup.active && coherence) {
          noteFeature("causal_coherence", {
            outcome: "suppressed",
            explanation: coherence.reason,
            suppressionReason: "behavioral warmup",
            thresholds: { zScore: coherence.zScore, threshold: _adaptiveThresholds.coherenceZScore },
          });
        } else if (coherence && !coherence.coherent && isSignatureSuppressed("causal_incoherence", _adaptiveThresholds)) {
          noteFeature("causal_coherence", {
            outcome: "suppressed",
            explanation: coherence.reason,
            suppressionReason: "adaptive signature suppression",
            thresholds: { zScore: coherence.zScore, threshold: _adaptiveThresholds.coherenceZScore },
          });
        }
        if (!_behaviorWarmup.active && coherence && !coherence.coherent && !isSignatureSuppressed("causal_incoherence", _adaptiveThresholds)) {
          // Check if the z-score exceeds the adaptive threshold (coherenceTracker may use global;
          // we post-filter here using the per-agent adaptive z-score)
          const exceedsAdaptive = !coherence.zScore || Math.abs(coherence.zScore) >= _adaptiveThresholds.coherenceZScore;
          if (exceedsAdaptive) {
            noteFeature("causal_coherence", {
              outcome: config.injectionDetection === "block" && coherence.severity === "high" ? "blocked" : "flagged",
              explanation: coherence.reason,
              thresholds: { zScore: coherence.zScore, threshold: _adaptiveThresholds.coherenceZScore },
            });
            const evt = buildCoherenceEvent(coherence,
              config.injectionDetection === "block" ? "blocked" : "flagged");
            const agentSession = agentTracker.getCurrentSession();
            evt.agentBuildId = agentSession?.agentBuildId;
            evt.agentLabel = agentSession?.agentLabel;
            evt.agentSessionId = agentSession?.sessionId;
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block" && coherence.severity === "high") {
              api.logger?.warn(`[shroud] BLOCKED causal incoherence: ${coherence.reason}`);
              return { block: true, blockReason: `Shroud security: ${coherence.reason}` };
            }
            api.logger?.info(`[shroud] Causal incoherence (flagged): ${coherence.reason}`);
          } else {
            noteFeature("causal_coherence", {
              outcome: "suppressed",
              explanation: coherence.reason,
              suppressionReason: "below adaptive z-score threshold",
              thresholds: { zScore: coherence.zScore, threshold: _adaptiveThresholds.coherenceZScore },
            });
          }
        } else if (!_behaviorWarmup.active && coherence) {
          noteFeature("causal_coherence", {
            outcome: "observed",
            explanation: `Causal coherence intact for ${event.toolName ?? "unknown"}.`,
            thresholds: { zScore: coherence.zScore, threshold: _adaptiveThresholds.coherenceZScore },
          });
        }
      }

      // --- Transformer sequence prediction: check tool-call surprise ---
      //     Pass the user intent vector from the drift detector so the model
      //     conditions its predictions on what the user actually asked for.
      if (_transformerScorer && _sessionToolSequence.length >= 3) {
        const intentVec = _driftDetector?.getProvider()
          ? (_driftDetector.getReferenceText()
            ? _driftDetector.getProvider().embed(_driftDetector.getReferenceText())
            : null)
          : null;
        const prediction = _transformerScorer.scoreToolCall(
          _sessionToolSequence,
          event.toolName ?? "unknown",
          intentVec,
          assessTrustZoneContext(event.toolName ?? "unknown", event.params),
        );
        const anomalyEvt = _transformerScorer.checkAnomaly(
          prediction,
          event.toolName ?? "unknown",
          agentTracker.getCurrentSession()?.agentLabel,
        );
        // Log softmax prediction for all tool calls (not just anomalies)
        if (prediction.topK.length > 0) {
          const topStr = prediction.topK.map(k => `${k.tool}=${(k.prob * 100).toFixed(1)}%`).join(" ");
          api.logger?.info(`[shroud] Transformer: ${event.toolName} surprise=${prediction.surprise.toFixed(3)} session=${prediction.sessionAnomalyScore.toFixed(3)} intent_attn=${prediction.intentAttention.toFixed(4)} top=[${topStr}]`);
        }
        // Use adaptive transformer threshold: suppress if below per-agent threshold
        if (_behaviorWarmup.active && anomalyEvt) {
          noteFeature("transformer", {
            outcome: "suppressed",
            explanation: anomalyEvt.description,
            suppressionReason: "behavioral warmup",
            thresholds: { surprise: prediction.surprise, threshold: _adaptiveThresholds.transformerThreshold },
          });
        } else if (anomalyEvt && prediction.surprise < _adaptiveThresholds.transformerThreshold) {
          noteFeature("transformer", {
            outcome: "suppressed",
            explanation: anomalyEvt.description,
            suppressionReason: "below adaptive transformer threshold",
            thresholds: { surprise: prediction.surprise, threshold: _adaptiveThresholds.transformerThreshold },
          });
        } else if (anomalyEvt && isSignatureSuppressed(anomalyEvt.signatureId, _adaptiveThresholds)) {
          noteFeature("transformer", {
            outcome: "suppressed",
            explanation: anomalyEvt.description,
            suppressionReason: "adaptive signature suppression",
            thresholds: { surprise: prediction.surprise, threshold: _adaptiveThresholds.transformerThreshold },
          });
        }
        if (!_behaviorWarmup.active
            && anomalyEvt && prediction.surprise >= _adaptiveThresholds.transformerThreshold
            && !isSignatureSuppressed(anomalyEvt.signatureId, _adaptiveThresholds)) {
          noteFeature("transformer", {
            outcome: config.injectionDetection === "block" && prediction.surprise > 0.95 ? "blocked" : "flagged",
            explanation: anomalyEvt.description,
            thresholds: {
              surprise: prediction.surprise,
              threshold: _adaptiveThresholds.transformerThreshold,
              intentAttention: prediction.intentAttention,
            },
          });
          const agentSession = agentTracker.getCurrentSession();
          anomalyEvt.agentBuildId = agentSession?.agentBuildId;
          anomalyEvt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(anomalyEvt);
          agentTracker.recordSecurityEvent(1);
          if (config.injectionDetection === "block" && prediction.surprise > 0.95) {
            api.logger?.warn(`[shroud] BLOCKED by transformer: surprise=${prediction.surprise.toFixed(3)}`);
            return { block: true, blockReason: `Shroud security: anomalous tool sequence (surprise=${prediction.surprise.toFixed(3)})` };
          }
        } else {
          noteFeature("transformer", {
            outcome: "observed",
            explanation: `Transformer scored ${event.toolName ?? "unknown"} at surprise=${prediction.surprise.toFixed(3)} without escalation.`,
            thresholds: {
              surprise: prediction.surprise,
              threshold: _adaptiveThresholds.transformerThreshold,
              intentAttention: prediction.intentAttention,
            },
          });
        }
      }

      // --- Multi-agent intent chain: capture delegation + check drift ---
      if (_intentChain) {
        const toolNameLower = (event.toolName ?? "").toLowerCase();
        // Capture delegation when agent spawns/sends to another agent
        if (toolNameLower === "sessions_send" || toolNameLower === "sessions_spawn") {
          const agentSession = agentTracker.getCurrentSession();
          if (agentSession) {
            const parentContract = resolveAgentContract(
              agentSession.agentLabel,
              agentSession.classification?.role || "General Agent",
            );
            const p = (typeof event.params === "object" && event.params !== null)
              ? event.params as Record<string, unknown>
              : {};
            const childHint = String(p.agentId || p.agentLabel || p.recipient || "").trim();
            const delegationText = String(p.message || p.content || p.text || p.body || "").trim();
            if (delegationText) {
              _intentLease.issueLease({
                parentAgentBuildId: agentSession.agentBuildId,
                parentAgentLabel: agentSession.agentLabel,
                childHint,
                intentSummary: delegationText,
                allowedToolFamilies: parentContract.allowedToolFamilies,
                allowedDataClasses: parentContract.allowedDataClasses,
                maxSteps: 8,
              });
            }
            _intentChain.captureDelegation(
              agentSession.agentBuildId,
              agentSession.agentLabel,
              agentSession.sessionId,
              event.params,
            );
          }
        }

        // Check delegation drift for sub-agents (depth >= 1)
        const agentSession = agentTracker.getCurrentSession();
        if (agentSession) {
          const delegDrift = _intentChain.checkDelegationDrift(
            agentSession.agentBuildId,
            event.toolName ?? "unknown",
            event.params,
          );
          if (delegDrift && delegDrift.drifted) {
            noteFeature("delegation_drift", {
              outcome: config.injectionDetection === "block" && delegDrift.severity === "high" ? "blocked" : "flagged",
              explanation: delegDrift.reason,
            });
            const evt = buildDelegationDriftEvent(
              agentSession.agentLabel,
              delegDrift,
              config.injectionDetection === "block" ? "blocked" : "flagged",
            );
            evt.agentBuildId = agentSession.agentBuildId;
            evt.agentLabel = agentSession.agentLabel;
            evt.agentSessionId = agentSession.sessionId;
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
            agentTracker.recordSecurityEvent(1);
            if (config.injectionDetection === "block" && delegDrift.severity === "high") {
              api.logger?.warn(`[shroud] BLOCKED delegation drift: ${delegDrift.reason}`);
              return { block: true, blockReason: `Shroud security: ${delegDrift.reason}` };
            }
            api.logger?.info(`[shroud] Delegation drift (flagged): ${delegDrift.reason}`);
          } else if (agentSession) {
            noteFeature("delegation_drift", {
              outcome: "observed",
              explanation: `Delegation chain remained aligned for ${agentSession.agentLabel}.`,
            });
          }
        }
      }

      // --- Vector store: accumulate tool sequence + track URLs ---
      {
        const tn = event.toolName ?? "unknown";
        _sessionToolSequence.push(tn);
        // Track URLs for cross-session correlation
        const toolNameLower = tn.toLowerCase();
        if (toolNameLower === "web_fetch" || toolNameLower === "fetch" || toolNameLower === "browser") {
          const p = (typeof event.params === "object" && event.params !== null)
            ? event.params as Record<string, unknown>
            : {};
          const url = String(p.url || p.uri || "");
          if (url) {
            _sessionUrls.push(url);
            // Check if URL is already known malicious
            if (_vectorStore && config.urlCorrelationEnabled) {
              const urlStatus = _vectorStore.isUrlMalicious(url);
              if (urlStatus.malicious) {
                noteFeature("url_correlation", {
                  outcome: config.injectionDetection === "block" ? "blocked" : "flagged",
                  explanation: `URL ${url} matched malicious correlation store (confidence=${urlStatus.confidence.toFixed(2)}).`,
                });
                const evt = buildUrlCorrelationEvent(url, urlStatus.confidence,
                  config.injectionDetection === "block" ? "blocked" : "flagged");
                const agentSession = agentTracker.getCurrentSession();
                evt.agentBuildId = agentSession?.agentBuildId;
                evt.agentLabel = agentSession?.agentLabel;
                evt.agentSessionId = agentSession?.sessionId;
                ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
                agentTracker.recordSecurityEvent(1);
                if (config.injectionDetection === "block") {
                  api.logger?.warn(`[shroud] BLOCKED malicious URL: ${url} (confidence=${urlStatus.confidence.toFixed(2)})`);
                  return { block: true, blockReason: `Shroud security: known malicious URL ${url}` };
                }
                api.logger?.warn(`[shroud] Malicious URL (flagged): ${url}`);
              } else {
                noteFeature("url_correlation", {
                  outcome: "observed",
                  explanation: `URL ${url} was not present in the malicious correlation store.`,
                });
              }
            }
          }
        }
      }

      // --- Shadow execution: deferred judgment for medium-severity events ---
      // When shadow is enabled and we have medium+ severity events that didn't
      // trigger an immediate block (high-severity checks above already returned),
      // run the tool call through the shadow treadmill before allowing it.
      if (_shadowExecutor && config.injectionDetection === "block" && _currentIntent) {
        // Check if any recent events from this tool call were medium+ severity
        const recentEvents = ((globalThis as any).__shroudSecurityBus || securityBus)?.getEvents() as SecurityEvent[] | undefined;
        const now = Date.now();
        const recentMedium = recentEvents?.filter((e: SecurityEvent) =>
          e.timestamp > now - 2000 && (e.severity === "medium" || e.severity === "high") &&
          e.matchedText?.startsWith(event.toolName ?? "")
        );

        if (recentMedium && recentMedium.length > 0) {
          noteFeature("shadow_execution", {
            outcome: "observed",
            explanation: `Shadow execution invoked for ${event.toolName} after ${recentMedium.length} medium/high precursor events.`,
          });
          api.logger?.info(`[shroud] Shadow execution triggered for "${event.toolName}" (${recentMedium.length} medium+ events)`);
          try {
            const shadowResult = await _shadowExecutor.execute({
              toolName: event.toolName ?? "unknown",
              params: event.params,
              intent: _currentIntent,
              honeypot: config.honeypotEnabled ? _honeypot : null,
              model: agentTracker.getCurrentSession()?.detectedModel || null,
              maxSteps: config.shadowExecutionMaxSteps,
              timeoutMs: config.shadowExecutionTimeoutMs,
              lastLlmBody: (globalThis as any).__shroudLastLlmBody || null,
            });

            // Emit shadow execution event for audit trail
            const shadowEvt = buildShadowEvent(shadowResult, shadowResult.verdict === "block" ? "blocked" : "flagged");
            const agentSession = agentTracker.getCurrentSession();
            shadowEvt.agentBuildId = agentSession?.agentBuildId;
            shadowEvt.agentLabel = agentSession?.agentLabel;
            shadowEvt.agentSessionId = agentSession?.sessionId;
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(shadowEvt);

            if (shadowResult.verdict === "block") {
              noteFeature("shadow_execution", {
                outcome: "blocked",
                explanation: shadowResult.verdictReason,
              });
              agentTracker.recordSecurityEvent(1);
              // Record attack trace for contrastive learning (Tier 2) + threat labels (Tier 4)
              if (_transformerScorer && _sessionToolSequence.length > 0) {
                const shadowToolNames = shadowResult.steps
                  .filter(s => s.llmResponse)
                  .flatMap(s => s.llmResponse!.toolCalls.map(tc => tc.name));
                const trace: AttackTrace = {
                  legitimatePrefix: [..._sessionToolSequence],
                  hijackedSuffix: [event.toolName ?? "unknown", ...shadowToolNames],
                  injectionPoint: _sessionToolSequence.length,
                  source: "shadow",
                  threatType: "shadow_exfil",
                  timestamp: Date.now(),
                };
                _transformerScorer.recordAttackTrace(trace);
                _transformerScorer.onShadowBlock(
                  shadowResult.verdictReason,
                  [..._sessionToolSequence],
                  [event.toolName ?? "unknown", ...shadowToolNames],
                );
                // Immune response: extract fingerprint + propagate antibodies fleet-wide
                if (_immuneEngine) {
                  const agentSession2 = agentTracker.getCurrentSession();
                  const fp = _immuneEngine.extractFingerprint(
                    trace, agentSession2?.agentBuildId || "", agentSession2?.agentLabel || "", "shadow",
                    "se_shadow_detected", [], [],
                  );
                  _immuneEngine.propagate(fp);
                }
              }
              api.logger?.warn(`[shroud] BLOCKED by shadow execution: ${shadowResult.verdictReason}`);
              return { block: true, blockReason: `Shroud shadow execution: ${shadowResult.verdictReason}` };
            }
            noteFeature("shadow_execution", {
              outcome: "flagged",
              explanation: shadowResult.verdictReason,
            });
            api.logger?.info(`[shroud] Shadow execution allowed: ${shadowResult.verdictReason}`);
          } catch (err: any) {
            noteFeature("shadow_execution", {
              outcome: "suppressed",
              explanation: `Shadow execution failed for ${event.toolName}: ${err?.message || "unknown error"}`,
              suppressionReason: "shadow execution error",
            });
            api.logger?.warn(`[shroud] Shadow execution error: ${err?.message}`);
          }
        }
      }
    }

    const serialized = JSON.stringify(event.params);
    const { text: deobfuscated, replacementCount } = ob().deobfuscateWithStats(serialized, "before_tool_call");

    if (serialized === deobfuscated) return;

    if (replacementCount > 0) agentTracker.recordDeobfuscation(replacementCount);
    api.logger?.info(
      `[shroud] before_tool_call(${event.toolName ?? "?"}): deobfuscated params (${replacementCount} replacements)`,
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

    // Collect PII categories from obfuscation for result validation
    const resultCategories = new Set<string>();
    let totalResultSize = 0;

    // Resolve per-tool field scope and per-agent category exemptions
    const toolName = _turnContext?.pendingToolCall?.toolName ?? event.toolName ?? "";
    const resolver = getFieldScopeResolver();
    const toolScope = resolver.resolveToolScope(toolName);
    const shouldScan = (field: string) => resolver.shouldScanField(field, toolScope);
    const agentSession = agentTracker.getCurrentSession();
    const exemptCategories = resolver.resolveAgentExemptions(
      agentSession?.agentLabel ?? "Unknown Agent",
      agentSession?.classification?.role ?? "General Agent",
    );

    const obfuscated = walkStringsScoped(event.message, (s) => {
      const result = ob().obfuscate(s, undefined, exemptCategories);
      totalResultSize += s.length;
      for (const entity of result.entities) {
        resultCategories.add(entity.category);
      }
      return result.obfuscated;
    }, shouldScan);

    // Validate tool result against user intent (Heuristic 1 + 3)
    if (_turnContext?.pendingToolCall && config.injectionDetection !== "off" && securityBus) {
      const flags = validateToolResult(_turnContext, resultCategories, totalResultSize);
      noteFeature("result_validation", {
        outcome: flags.length > 0 ? "flagged" : "observed",
        explanation: flags.length > 0
          ? `Tool result validation raised ${flags.length} result-risk flags for ${_turnContext.pendingToolCall.toolName}.`
          : `Tool result validation cleared ${_turnContext.pendingToolCall.toolName}.`,
      });
      if (flags.length > 0) {
        const agentSession = agentTracker.getCurrentSession();
        for (const evt of flags) {
          evt.agentBuildId = agentSession?.agentBuildId;
          evt.agentLabel = agentSession?.agentLabel;
          evt.agentSessionId = agentSession?.sessionId;
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
        }
        agentTracker.recordSecurityEvent(flags.length);
      }

      // Record result for cross-tool correlation (Heuristic 2 in next before_tool_call)
      _turnContext.toolResults.push({
        toolName: _turnContext.pendingToolCall.toolName,
        category: _turnContext.pendingToolCall.category,
        resultCategories,
        resultSize: totalResultSize,
      });

      // --- Causal coherence: feed result text for next pair check ---
      if (_coherenceTracker && _turnContext.pendingToolCall) {
        // Extract text from the obfuscated result for embedding
        const resultText = typeof event.message === "string"
          ? event.message
          : JSON.stringify(event.message);
        _coherenceTracker.feedResult(_turnContext.pendingToolCall.toolName, resultText);
      }

      _turnContext.pendingToolCall = null;
    }

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
      const { text: deobfuscated, replacementCount: _msRc } = ob().deobfuscateWithStats(event.content, "message_sending");
      if (_msRc > 0) {
        agentTracker.recordDeobfuscation(_msRc);
        api.logger?.info("[shroud] message_sending: deobfuscated outbound message");
        if (auditActive) {
          try {
            emitDeobfuscationAudit(api.logger, config, randomBytes(8).toString("hex"), _msRc);
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
      let _msBlockRc = 0;
      const newContent = event.content.map((block: any) => {
        if (block && typeof block === "object") {
          if (typeof block.text === "string") {
            const { text: deob, replacementCount: rc } = ob().deobfuscateWithStats(block.text, "message_sending");
            if (deob !== block.text) { _msBlockRc += rc; return { ...block, text: deob }; }
          }
          if (typeof block.content === "string") {
            const { text: deob, replacementCount: rc } = ob().deobfuscateWithStats(block.content, "message_sending");
            if (deob !== block.content) { _msBlockRc += rc; return { ...block, content: deob }; }
          }
        }
        return block;
      });
      if (_msBlockRc > 0) agentTracker.recordDeobfuscation(_msBlockRc);
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
              const { text: deob, replacementCount: _esRc } = ob().deobfuscateWithStats(block.text, "event_stream");
              if (deob !== block.text) {
                block.text = deob;
                if (_esRc > 0) agentTracker.recordDeobfuscation(_esRc);
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
    const { text: deob, replacementCount: _gdRc } = ob().deobfuscateWithStats(text, "global_hook");
    if (_gdRc > 0) agentTracker.recordDeobfuscation(_gdRc);
    return deob;
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

    // Store original for comparison — SDK clients may have captured it
    const _prePatchFetch = globalThis.fetch;

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
      agentTracker.markCallStart();
      const callSession = agentTracker.recordLlmCall();
      _callUrl = url;
      _callModel = "";

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

        // Capture last LLM request body for shadow execution
        if (_shadowExecutor) {
          (globalThis as any).__shroudLastLlmBody = body;
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
        // Agent identity: before_prompt_build + registry is the primary source.
        // The fetch intercept is the FALLBACK — only used if before_prompt_build
        // couldn't identify the agent (e.g. WhatsApp with no conversation_label).
        if (systemForIdentity && systemForIdentity.length > 10) {
          const existing = agentTracker.getCurrentSession();
          if (!existing || existing.agentLabel === "Unknown Agent" || existing.sessionId === "transient") {
            // before_prompt_build failed — try registry + full extraction as fallback
            const registryName = agentRegistry.resolve(systemForIdentity);
            const session = agentTracker.registerAgent(systemForIdentity, [], "unknown", false, registryName || undefined);
            if (profiler) profiler.setAgentBuildId(session.agentBuildId);
          } else {
            if (profiler) profiler.setAgentBuildId(existing.agentBuildId);
          }
        }

        // Extract tool inventory from body.tools
        if (Array.isArray(body.tools) && body.tools.length > 0) {
          const toolNames = body.tools
            .map((t: any) => t?.name || t?.function?.name || "")
            .filter((n: string) => n.length > 0);
          if (toolNames.length > 0) {
            agentTracker.updateTools(toolNames);
            if (profiler) profiler.setToolInventory(toolNames);
          }
        }

        // Extract SOUL.md / agent identity from messages and system blocks.
        // OpenClaw buries it in the conversation history — scan broadly.
        if (!agentTracker.getCurrentSession()?.soulExtract) {
          const soulPatterns = /(?:-\s*Name:|[Yy]ou\s+are\s+(?:a\s+|an\s+)?[A-Z]|SOUL|IDENTITY|personality|role:|purpose:|[Yy]our\s+(?:name|role|job|purpose)\s+is)/;

          // 1. Check system blocks (Anthropic array format)
          if (Array.isArray(body.system)) {
            for (const block of body.system) {
              const t = block?.text || "";
              if (t.length > 30 && soulPatterns.test(t) && !t.startsWith("You are Claude Code") && !/^You are a personal assistant/i.test(t)) {
                agentTracker.updateSoul(t);
                break;
              }
            }
          }

          // 2. Scan messages — check first 20, prefer assistant role
          if (!agentTracker.getCurrentSession()?.soulExtract && Array.isArray(body.messages)) {
            for (let mi = 0; mi < Math.min(20, body.messages.length); mi++) {
              const m = body.messages[mi];
              let text = "";
              if (typeof m?.content === "string") {
                text = m.content;
              } else if (Array.isArray(m?.content)) {
                text = m.content.map((b: any) => b?.text || "").join("\n");
              }
              if (text.length > 30 && soulPatterns.test(text) && !text.startsWith("You are Claude Code")) {
                agentTracker.updateSoul(text);
                break;
              }
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
          // OpenAI: tool_calls in assistant messages (multi-turn re-obfuscation)
          if (Array.isArray(msg.tool_calls)) {
            for (const tc of msg.tool_calls) {
              if (typeof tc.function?.arguments === "string") {
                const r = obfuscateText(tc.function.arguments);
                if (r.modified) { tc.function.arguments = r.text; modified = true; }
              }
              if (typeof tc.function?.name === "string") {
                const r = obfuscateText(tc.function.name);
                if (r.modified) { tc.function.name = r.text; modified = true; }
              }
            }
          }
        }

        // --- Security: request-side injection scanning (Track 1) ---
        // Runs AFTER obfuscation, scans the ORIGINAL text (pre-obfuscation)
        // for injection patterns. Does NOT modify the request body.
        const activeDetector = getDetectorForAgent();
        if (activeDetector && securityBus) {
          try {
            // Scan system prompt (trusted, OC-generated) separately — skip token-smuggling
            // detection to avoid firing on Shroud's own canary tokens injected there.
            const trustedTexts: string[] = [];
            if (typeof body.system === "string") trustedTexts.push(body.system);
            if (typeof body.instructions === "string") trustedTexts.push(body.instructions);

            // Collect untrusted message content (user + tool_result) for full scanning
            const textsToScan: string[] = [];
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

            // Scan trusted content (no token-smuggling), then untrusted content (full scan)
            const allText = [...trustedTexts, ...textsToScan].join("\n");
            const events = [
              ...(trustedTexts.length > 0
                ? activeDetector.scanRequest(trustedTexts.join("\n"), { skipTokenSmuggling: true })
                : []),
              ...(textsToScan.length > 0
                ? activeDetector.scanRequest(textsToScan.join("\n"))
                : []),
            ];
            noteFeature("injection_signatures", {
              outcome: events.length > 0
                ? (events.some(e => e.action === "blocked") ? "blocked" : "flagged")
                : "observed",
              explanation: events.length > 0
                ? `Fetch-side request scan matched ${events.length} injection signatures.`
                : "Fetch-side request scan found no injection signatures.",
            });

            // Enrich events with agent identity
            const agentSession = agentTracker.getCurrentSession();
            for (const evt of events) {
              if (agentSession) {
                evt.agentBuildId = agentSession.agentBuildId;
                evt.agentLabel = agentSession.agentLabel;
              evt.channel = agentSession.channels?.[agentSession.channels.length - 1];
                evt.agentSessionId = agentSession.sessionId;
              }
              ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
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
    // Current LLM call metadata for logging
    let _callUrl = "";
    let _callModel = "";

    /** Scan deobfuscated response text for security events. Called per-block. */
    function scanDeobfuscatedBlock(deobbed: string): void {
      responseTextAccum += deobbed;

      // Response-side injection scanning (Track 1)
      const respDetector = getDetectorForAgent();
      if (respDetector && securityBus) {
        try {
          const events = respDetector.scanResponse(deobbed);
          noteFeature("injection_signatures", {
            outcome: events.length > 0 ? "flagged" : "observed",
            explanation: events.length > 0
              ? `Response scan matched ${events.length} suspicious response signatures.`
              : "Response scan found no injection signatures.",
          });
          const agentSession = agentTracker.getCurrentSession();
          for (const evt of events) {
            if (agentSession) {
              evt.agentBuildId = agentSession.agentBuildId;
              evt.agentLabel = agentSession.agentLabel;
              evt.channel = agentSession.channels?.[agentSession.channels.length - 1];
              evt.agentSessionId = agentSession.sessionId;
            }
            ((globalThis as any).__shroudSecurityBus || securityBus)?.emit(evt);
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
          noteFeature("canary", {
            outcome: allLeaks.length > 0 ? "flagged" : "observed",
            explanation: allLeaks.length > 0
              ? `Canary/behavioural tripwire leaked ${allLeaks.length} times in model output.`
              : "No canary leakage detected in response block.",
          });
          if (allLeaks.length > 0) {
            const agentSession = agentTracker.getCurrentSession();
            for (const leak of allLeaks) {
              ((globalThis as any).__shroudSecurityBus || securityBus)?.emit({
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
      // Record heartbeat if this was a heartbeat call
      if ((globalThis as any).__shroudCurrentHeartbeat) {
        (globalThis as any).__shroudCurrentHeartbeat = false;
        const hbAlert = agentTracker.recordHeartbeat(responseTextAccum);
        if (hbAlert && securityBus) {
          const agentSession = agentTracker.getCurrentSession();
          ((globalThis as any).__shroudSecurityBus || securityBus)?.emit({
            timestamp: Date.now(),
            eventType: "anomaly_detected",
            direction: "response",
            threatClass: "instruction_override" as any,
            signatureId: "heartbeat_alert",
            severity: hbAlert.severity,
            matchedText: hbAlert.alert,
            matchStart: 0, matchEnd: 0, textLength: responseTextAccum.length,
            action: "flagged",
            description: hbAlert.alert,
            agentBuildId: agentSession?.agentBuildId,
            agentLabel: agentSession?.agentLabel,
            agentSessionId: agentSession?.sessionId,
            channel: "heartbeat",
          });
        }
      }

      if (profiler && responseTextAccum.length > 0) {
        try {
          const fv = profiler.extractResponseFeatures(responseTextAccum, [], responseCacheUsage ?? undefined);
          if (fv) {
            const alerts = profiler.analyzeTurn(fv);
            // Emit anomaly alerts as security events
            if (alerts.length > 0 && securityBus) {
              const agentSession = agentTracker.getCurrentSession();
              for (const alert of alerts) {
                ((globalThis as any).__shroudSecurityBus || securityBus)?.emit({
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
          // Per-agent cache anomaly detection
          if (responseCacheUsage && responseCacheUsage.inputTokens > 0) {
            const cacheAlert = agentTracker.updateCache(responseCacheUsage);
            if (cacheAlert && securityBus) {
              const agentSession = agentTracker.getCurrentSession();
              ((globalThis as any).__shroudSecurityBus || securityBus)?.emit({
                timestamp: Date.now(),
                eventType: "anomaly_detected",
                direction: "response",
                threatClass: "instruction_override" as any,
                signatureId: "cache_anomaly",
                severity: cacheAlert.severity,
                matchedText: cacheAlert.alert,
                matchStart: 0, matchEnd: 0,
                textLength: 0,
                action: "flagged",
                description: cacheAlert.alert,
                agentBuildId: agentSession?.agentBuildId,
                agentLabel: agentSession?.agentLabel,
                agentSessionId: agentSession?.sessionId,
              });
              agentTracker.recordSecurityEvent(1);
            }
          }

          // Incremental baseline update — flush to disk every 5 turns
          // so baselines build up without waiting for session end / SIGTERM
          const profile = profiler.getSessionProfile();
          if (profile.turns.length > 0 && profile.turns.length % 5 === 0) {
            _flushToDiskAsync().catch(() => {});
          }
        } catch { /* never break response pipeline */ }
      }
      // Log the completed LLM call
      if (responseCacheUsage) {
        const currentAgent = agentTracker.getCurrentSession();
        agentTracker.logCall({
          url: _callUrl || "",
          model: currentAgent?.detectedModel || _callModel || "unknown",
          inputTokens: responseCacheUsage.inputTokens,
          outputTokens: responseCacheUsage.outputTokens,
          cacheReadTokens: responseCacheUsage.cacheReadTokens,
          cacheWriteTokens: responseCacheUsage.cacheWriteTokens,
          channel: currentAgent?.channels?.[currentAgent.channels.length - 1] || "",
          securityEvents: 0,
          reason: _callReason || "LLM call",
        });
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
        // OpenAI tool_calls per-choice state: Map<choiceIdx, Map<toolCallIdx, argString>>
        const toolCallAccum: Map<number, Map<number, string>> = new Map();
        const toolCallBuffer: Map<number, string[]> = new Map();

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
                  const { text: _deobText, replacementCount: _deobRc } = ob().deobfuscateWithStats(accumulated);
                  let deobbed = _deobText;
                  if (_deobRc > 0) agentTracker.recordDeobfuscation(_deobRc);
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

              // OpenAI delta.content / delta.tool_calls: buffer until finish_reason
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
                  // Buffer tool_calls argument fragments
                  if (Array.isArray(choice.delta?.tool_calls)) {
                    for (const tc of choice.delta.tool_calls) {
                      const tcIdx = tc.index ?? 0;
                      if (!toolCallAccum.has(idx)) toolCallAccum.set(idx, new Map());
                      const tcMap = toolCallAccum.get(idx)!;
                      if (typeof tc.function?.arguments === "string") {
                        tcMap.set(tcIdx, (tcMap.get(tcIdx) || "") + tc.function.arguments);
                      }
                    }
                    if (!toolCallBuffer.has(idx)) toolCallBuffer.set(idx, []);
                    toolCallBuffer.get(idx)!.push(part);
                    buffered = true;
                  }
                  // finish_reason signals block complete — flush
                  if (choice.finish_reason) {
                    // Flush text content
                    const accumulated = choiceAccum.get(idx);
                    const buf = choiceBuffer.get(idx);
                    if (accumulated && buf && buf.length > 0) {
                      const { text: _deobText2, replacementCount: _deobRc2 } = ob().deobfuscateWithStats(accumulated);
                      let deobbed = _deobText2;
                      if (_deobRc2 > 0) agentTracker.recordDeobfuscation(_deobRc2);
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
                    // Flush tool_calls — deobfuscate accumulated arguments
                    const tcMap = toolCallAccum.get(idx);
                    const tcBuf = toolCallBuffer.get(idx);
                    if (tcMap && tcMap.size > 0 && tcBuf && tcBuf.length > 0) {
                      // Deobfuscate each tool call's accumulated arguments
                      const deobArgs: Map<number, string> = new Map();
                      for (const [tcIdx, args] of tcMap) {
                        const { text: deobArg, replacementCount: tcRc } = ob().deobfuscateWithStats(args);
                        deobArgs.set(tcIdx, deobArg);
                        if (tcRc > 0) agentTracker.recordDeobfuscation(tcRc);
                      }
                      // Track per-tool-call whether we've emitted the deobbed args
                      const tcEmitted: Set<number> = new Set();
                      for (const eventStr of tcBuf) {
                        const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                        if (dLine) {
                          try {
                            const dJson = JSON.parse(dLine.slice(6));
                            if (Array.isArray(dJson.choices)) {
                              for (const c of dJson.choices) {
                                if (Array.isArray(c.delta?.tool_calls)) {
                                  for (const tc of c.delta.tool_calls) {
                                    const tcIdx = tc.index ?? 0;
                                    if (typeof tc.function?.arguments === "string") {
                                      const deob = deobArgs.get(tcIdx);
                                      if (deob !== undefined) {
                                        if (!tcEmitted.has(tcIdx)) {
                                          tc.function.arguments = deob;
                                          tcEmitted.add(tcIdx);
                                        } else {
                                          tc.function.arguments = "";
                                        }
                                      }
                                    }
                                  }
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
                      toolCallAccum.delete(idx);
                      toolCallBuffer.delete(idx);
                    }
                    buffered = false;
                  }
                }
                if (buffered) continue;
              }

              // Extract LLM cache usage from message_start (Anthropic) or stream events (OpenAI)
              const usage = json.message?.usage || json.usage;
              if (usage) {
                const cacheRead = usage.cache_read_input_tokens || usage.prompt_tokens_details?.cached_tokens || 0;
                const cacheWrite = usage.cache_creation_input_tokens || 0;
                // Anthropic: input_tokens is the non-cached portion.
                // Total input = input_tokens + cache_read + cache_write
                const rawInput = usage.input_tokens || usage.prompt_tokens || 0;
                const totalInput = rawInput + cacheRead + cacheWrite;
                responseCacheUsage = {
                  inputTokens: totalInput,
                  outputTokens: usage.output_tokens || usage.completion_tokens || 0,
                  cacheReadTokens: cacheRead,
                  cacheWriteTokens: cacheWrite,
                };
              }

              // Deobfuscate content blocks in message events (message_start etc)
              if (Array.isArray(json.message?.content)) {
                for (const block of json.message.content) {
                  if (block?.type === "text" && typeof block.text === "string") {
                    const { text: _dt, replacementCount: _drc } = ob().deobfuscateWithStats(block.text);
                    block.text = _dt;
                    if (_drc > 0) agentTracker.recordDeobfuscation(_drc);
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
              const { text: deobbed, replacementCount: _flushRc } = ob().deobfuscateWithStats(accumulated);
              if (_flushRc > 0) agentTracker.recordDeobfuscation(_flushRc);
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
              const { text: deobbed, replacementCount: _flushRc2 } = ob().deobfuscateWithStats(accumulated);
              if (_flushRc2 > 0) agentTracker.recordDeobfuscation(_flushRc2);
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
            // Flush any remaining tool_calls buffers
            for (const [idx, tcBuf] of toolCallBuffer) {
              const tcMap = toolCallAccum.get(idx);
              if (tcMap && tcMap.size > 0 && tcBuf.length > 0) {
                const deobArgs: Map<number, string> = new Map();
                for (const [tcIdx, args] of tcMap) {
                  const { text: deobArg, replacementCount: tcFlushRc } = ob().deobfuscateWithStats(args);
                  deobArgs.set(tcIdx, deobArg);
                  if (tcFlushRc > 0) agentTracker.recordDeobfuscation(tcFlushRc);
                }
                const tcEmitted: Set<number> = new Set();
                for (const eventStr of tcBuf) {
                  const dLine = eventStr.split("\n").find((l: string) => l.startsWith("data: "));
                  if (dLine) {
                    try {
                      const dJson = JSON.parse(dLine.slice(6));
                      if (Array.isArray(dJson.choices)) {
                        for (const c of dJson.choices) {
                          if (Array.isArray(c.delta?.tool_calls)) {
                            for (const tc of c.delta.tool_calls) {
                              const tcIdx = tc.index ?? 0;
                              if (typeof tc.function?.arguments === "string") {
                                const deob = deobArgs.get(tcIdx);
                                if (deob !== undefined) {
                                  if (!tcEmitted.has(tcIdx)) {
                                    tc.function.arguments = deob;
                                    tcEmitted.add(tcIdx);
                                  } else {
                                    tc.function.arguments = "";
                                  }
                                }
                              }
                            }
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
            const jCacheRead = jsonUsage.cache_read_input_tokens || jsonUsage.prompt_tokens_details?.cached_tokens || 0;
            const jCacheWrite = jsonUsage.cache_creation_input_tokens || 0;
            const jRawInput = jsonUsage.input_tokens || jsonUsage.prompt_tokens || 0;
            responseCacheUsage = {
              inputTokens: jRawInput + jCacheRead + jCacheWrite,
              outputTokens: jsonUsage.output_tokens || jsonUsage.completion_tokens || 0,
              cacheReadTokens: jCacheRead,
              cacheWriteTokens: jCacheWrite,
            };
          }
          if (Array.isArray(json.content)) {
            for (const block of json.content) {
              if (block?.type === "text" && typeof block.text === "string") {
                const { text: _jdt, replacementCount: _jdrc } = ob().deobfuscateWithStats(block.text);
                block.text = _jdt;
                if (_jdrc > 0) agentTracker.recordDeobfuscation(_jdrc);
                scanDeobfuscatedBlock(block.text);
              }
            }
          }
          if (Array.isArray(json.choices)) {
            for (const choice of json.choices) {
              if (typeof choice.message?.content === "string") {
                const { text: _jdt2, replacementCount: _jdrc2 } = ob().deobfuscateWithStats(choice.message.content);
                choice.message.content = _jdt2;
                if (_jdrc2 > 0) agentTracker.recordDeobfuscation(_jdrc2);
                scanDeobfuscatedBlock(choice.message.content);
              }
              // OpenAI: deobfuscate tool_calls arguments
              if (Array.isArray(choice.message?.tool_calls)) {
                for (const tc of choice.message.tool_calls) {
                  if (typeof tc.function?.arguments === "string") {
                    const { text: _jdt3, replacementCount: _jdrc3 } = ob().deobfuscateWithStats(tc.function.arguments);
                    tc.function.arguments = _jdt3;
                    if (_jdrc3 > 0) agentTracker.recordDeobfuscation(_jdrc3);
                  }
                }
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

    // ── Rebind SDK clients that captured the pre-patch fetch reference ──
    // The OpenAI SDK (and others) capture `globalThis.fetch` at construction
    // time via `this.fetch = options.fetch ?? getDefaultFetch()`. If the SDK
    // was constructed before Shroud patched fetch, it holds the original
    // unpatched reference and all LLM requests bypass the intercept.
    // Walk all reachable objects looking for SDK client instances that still
    // hold the old reference and rebind them to the patched interceptor.
    try {
      const patchedFetch = globalThis.fetch;
      const visited = new WeakSet();
      function rebindSdkClients(obj: any, depth: number): void {
        if (!obj || typeof obj !== "object" || depth > 4 || visited.has(obj)) return;
        visited.add(obj);
        // OpenAI SDK: client.fetch === old unpatched fetch
        if (obj.fetch === _prePatchFetch && obj.fetch !== patchedFetch) {
          obj.fetch = patchedFetch;
          api.logger?.info("[shroud] rebound SDK client fetch to patched interceptor");
        }
        // Check known extension paths
        try {
          for (const key of Object.keys(obj)) {
            if (key.startsWith("_") || key === "constructor") continue;
            try { rebindSdkClients(obj[key], depth + 1); } catch {}
          }
        } catch {}
      }
      // Scan globalThis for SDK client instances
      rebindSdkClients((globalThis as any).__ocClients, 0);
      rebindSdkClients((globalThis as any).__openaiClient, 0);
      // Scan all loaded modules for exported clients
      if (typeof require !== "undefined" && (require as any).cache) {
        for (const modId of Object.keys((require as any).cache)) {
          if (modId.includes("openai") || modId.includes("lossless")) {
            try {
              const mod = (require as any).cache[modId]?.exports;
              rebindSdkClients(mod, 0);
            } catch {}
          }
        }
      }
    } catch {
      // Non-fatal — fetch intercept still works for globalThis.fetch callers
    }

  }
}
