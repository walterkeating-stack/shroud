#!/usr/bin/env node
/**
 * APP Server — Agent Privacy Protocol reference implementation.
 *
 * Implements APP-RFC-0001 Level 3 (Enterprise) compliance.
 * Wraps the Shroud obfuscation engine and exposes all APP methods
 * over newline-delimited JSON-RPC on stdio.
 *
 * Security extension: when security modules are available (feature/transformer
 * build), the APP server integrates injection detection, agent tracking, and
 * event shipping. Clients MUST call `identify` before obfuscate/deobfuscate.
 *
 * Usage:
 *   node app-server.mjs [dist-path]
 *
 * Environment:
 *   SHROUD_PLUGIN_CONFIG   JSON config for the engine
 *   SHROUD_STATS_FILE      Optional stats dump file override
 *   SHROUD_APP_EVENTS_FILE Optional JSONL file for security events (dashboard bridge)
 *   SHROUD_APP_SESSIONS_FILE Optional legacy session file override
 */

import { createHash, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { resolve, dirname } from "node:path";
import { writeFileSync, readFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const shroudDist = process.argv[2] || resolve(__dirname, "dist");

// ---------------------------------------------------------------------------
// Load engine
// ---------------------------------------------------------------------------

const { Obfuscator } = await import(
  pathToFileURL(resolve(shroudDist, "obfuscator.js")).href
);
const { resolveConfig } = await import(
  pathToFileURL(resolve(shroudDist, "config.js")).href
);
const { DnsCache } = await import(
  pathToFileURL(resolve(shroudDist, "dns-cache.js")).href
);
const { resolveRuntimePaths, resolveAppSessionOutputPath, resolveAppStatsOutputPath } = await import(
  pathToFileURL(resolve(shroudDist, "runtime.js")).href
);

// Read version from package.json
let engineVersion = "0.0.0";
try {
  const pkg = JSON.parse(readFileSync(resolve(__dirname, "package.json"), "utf8"));
  engineVersion = pkg.version || engineVersion;
} catch { /* best-effort */ }

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

let pluginConfig = {};
if (process.env.SHROUD_PLUGIN_CONFIG) {
  try {
    pluginConfig = JSON.parse(process.env.SHROUD_PLUGIN_CONFIG);
  } catch (e) {
    process.stderr.write(`[app-server] Bad SHROUD_PLUGIN_CONFIG: ${e.message}\n`);
  }
}

let config = resolveConfig(pluginConfig);
let obfuscator = new Obfuscator(config);
const runtime = resolveRuntimePaths(config, process.env);
const STATS_FILE = process.env.SHROUD_STATS_FILE || resolveAppStatsOutputPath(runtime, { pid: process.pid });
const APP_EVENTS_FILE = process.env.SHROUD_APP_EVENTS_FILE || runtime.appEventsFile;
let appSessionFile = process.env.SHROUD_APP_SESSIONS_FILE || null;
const PUBLIC_DOMAINS = [
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
const URL_RE = /https?:\/\/[^\s<>"')\]]+[^\s<>"')\].,;:!?]/g;

function ensureParentDir(filePath) {
  try {
    mkdirSync(dirname(filePath), { recursive: true });
  } catch {
    // best-effort
  }
}

function getSessionFilePath() {
  if (!appSessionFile) {
    appSessionFile = resolveAppSessionOutputPath(runtime, {
      agentLabel,
      agentBuildId,
      pid: process.pid,
    });
  }
  return appSessionFile;
}

ensureParentDir(STATS_FILE);
ensureParentDir(APP_EVENTS_FILE);

function getDnsCache() {
  const g = globalThis;
  if (!g.__shroudDnsCache) {
    const cache = new DnsCache();
    for (const domain of PUBLIC_DOMAINS) {
      cache.seed(domain, "0.0.0.1", true);
      if (!domain.startsWith("www.")) {
        cache.seed("www." + domain, "0.0.0.1", true);
      }
    }
    g.__shroudDnsCache = cache;
  }
  return g.__shroudDnsCache;
}

function stripSlackForDns(text) {
  return text
    .replace(/<mailto:[^|>]+\|([^>]*)>/g, "$1")
    .replace(/<(https?:\/\/[^|>]+)\|[^>]*>/g, "$1")
    .replace(/<(https?:\/\/[^>]+)>/g, "$1");
}

async function warmPublicUrlCache(text) {
  if (typeof text !== "string" || text.length === 0) return;
  const cache = getDnsCache();
  const cleaned = stripSlackForDns(text);
  const urls = [...new Set([...cleaned.matchAll(URL_RE)].map((m) => m[0]))];
  if (urls.length === 0) return;
  try {
    await cache.warmCache(urls);
  } catch {
    // DNS failures are non-fatal; unknown URLs will still obfuscate.
  }
}

// ---------------------------------------------------------------------------
// Security modules (optional — degrade gracefully if not built)
// ---------------------------------------------------------------------------

let SecurityEventBus = null;
let InjectionDetector = null;
let scanToolCall = null;
let classifyAgent = null;
let classifyAgentWithTools = null;
let securityBus = null;
let injectionDetector = null;
let securityEnabled = false;

// Tool sequence tracking (for profiling + transformer)
const toolSequence = [];
// Agent classification (inferred from text on first obfuscate calls)
let agentClassification = null;
let classificationTextSampled = 0;
let classificationTextBuffer = "";

try {
  const secMod = await import(pathToFileURL(resolve(shroudDist, "security-event.js")).href);
  SecurityEventBus = secMod.SecurityEventBus;

  const injMod = await import(pathToFileURL(resolve(shroudDist, "detectors", "injection.js")).href);
  InjectionDetector = injMod.InjectionDetector;

  const guardMod = await import(pathToFileURL(resolve(shroudDist, "detectors", "tool-guard.js")).href);
  scanToolCall = guardMod.scanToolCall;

  const agentMod = await import(pathToFileURL(resolve(shroudDist, "agent-session.js")).href);
  classifyAgent = agentMod.classifyAgent;
  classifyAgentWithTools = agentMod.classifyAgentWithTools;

  if (config.injectionDetection !== "off") {
    securityBus = new SecurityEventBus(5000, 60_000);
    injectionDetector = new InjectionDetector({
      action: config.injectionDetection || "flag",
      disabledSignatures: new Set(config.injectionDisabledSignatures || []),
      minSeverity: config.injectionMinSeverity || "low",
      scanResponses: config.injectionScanResponses ?? false,
    });
    securityEnabled = true;

    // Ship events to JSONL file for dashboard bridge
    securityBus.onEvent((event) => {
      try {
        appendFileSync(APP_EVENTS_FILE, JSON.stringify(event) + "\n");
      } catch { /* best-effort */ }
    });

    process.stderr.write(`[app-server] Security enabled: injection=${config.injectionDetection || "flag"}\n`);
  }
} catch {
  process.stderr.write("[app-server] Security modules not available (core-only build)\n");
}

// ---------------------------------------------------------------------------
// Agent identity (required before obfuscate/deobfuscate)
// ---------------------------------------------------------------------------

let agentIdentified = false;
let agentLabel = null;
let agentBuildId = null;
let agentVersion = null;
let agentChannel = null;

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

let chainHash = "0000000000000000";

function advanceChain(data) {
  const payload = chainHash + JSON.stringify(data);
  chainHash = createHash("sha256").update(payload).digest("hex").slice(0, 16);
  return chainHash;
}

function proofHash(text) {
  const salt = config.auditHashSalt || "";
  const truncate = config.auditHashTruncate || 12;
  return createHash("sha256")
    .update(salt + text)
    .digest("hex")
    .slice(0, truncate);
}

// ---------------------------------------------------------------------------
// Partition support (namespace prefix on the single store)
// ---------------------------------------------------------------------------

let activePartition = null;
const partitionObfuscators = new Map();

function getObfuscator() {
  if (!activePartition) return obfuscator;
  if (!partitionObfuscators.has(activePartition)) {
    partitionObfuscators.set(activePartition, new Obfuscator(config));
  }
  return partitionObfuscators.get(activePartition);
}

function resolvePartition(params) {
  // Per-request partition override
  if (params?.partition) {
    if (!partitionObfuscators.has(params.partition)) {
      partitionObfuscators.set(params.partition, new Obfuscator(config));
    }
    return partitionObfuscators.get(params.partition);
  }
  return getObfuscator();
}

// ---------------------------------------------------------------------------
// Request tracking
// ---------------------------------------------------------------------------

const startTime = Date.now();
let requestCount = 0;
let totalProcessingMs = 0;

// Per-agent privacy counters (for dashboard)
const privacy = {
  obfuscationCalls: 0,
  deobfuscationCalls: 0,
  entitiesObfuscated: 0,
  replacementsDeobfuscated: 0,
  categoryCounts: {},
};

// System prompt fingerprinting — detects prompt changes between calls.
// Uses SHA-256 of the first obfuscation text (typically the system prompt).
let promptFingerprint = null;     // { hash: string, firstSeen: number, turnCount: number }
let promptFingerprintDrifts = 0;

function checkPromptFingerprint(text) {
  if (!agentIdentified || text.length < 50) return;

  const hash = createHash("sha256").update(text).digest("hex").slice(0, 16);

  if (!promptFingerprint) {
    promptFingerprint = { hash, firstSeen: Date.now(), turnCount: 1 };
    return;
  }

  promptFingerprint.turnCount++;

  if (hash !== promptFingerprint.hash) {
    promptFingerprintDrifts++;
    process.stderr.write(
      `[app-server] System prompt fingerprint changed: ${promptFingerprint.hash} → ${hash} (turn ${promptFingerprint.turnCount})\n`
    );
    if (securityBus) {
      securityBus.emit({
        timestamp: Date.now(),
        eventType: "anomaly_detected",
        direction: "request",
        severity: "high",
        threatClass: "prompt_fingerprint_drift",
        description: `System prompt fingerprint changed for ${agentLabel}: ${promptFingerprint.hash} → ${hash}`,
        details: `Prompt hash changed at turn ${promptFingerprint.turnCount}. May indicate injection or reconfiguration.`,
        agentBuildId,
        agentLabel,
      });
    }
    // Update baseline to new hash (track the change, don't keep alerting)
    promptFingerprint.hash = hash;
    promptFingerprint.firstSeen = Date.now();
  }
}

// ---------------------------------------------------------------------------
// Stats dump helper
// ---------------------------------------------------------------------------

function dumpStats() {
  try {
    const stats = getObfuscator().getStats();
    stats.updatedAt = new Date().toISOString();
    stats.pid = process.pid;
    ensureParentDir(STATS_FILE);
    writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2) + "\n");
  } catch { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// Session file dump (for dashboard visibility)
// ---------------------------------------------------------------------------

function dumpSessionFile() {
  if (!agentIdentified) return;
  try {
    const sessionFile = getSessionFilePath();
    const session = {
      agentLabel,
      agentBuildId,
      agentVersion,
      channel: agentChannel,
      source: "app-server",
      pid: process.pid,
      requestCount,
      uptimeMs: Date.now() - startTime,
      securityEvents: securityBus ? securityBus.getEvents().length : 0,
      storeSize: getObfuscator().getStats().storeMappings ?? 0,
      classification: agentClassification,
      toolSequence: toolSequence.slice(-20),
      privacy,
      promptFingerprint: promptFingerprint ? {
        hash: promptFingerprint.hash,
        firstSeen: new Date(promptFingerprint.firstSeen).toISOString(),
        turnCount: promptFingerprint.turnCount,
        drifts: promptFingerprintDrifts,
      } : null,
      updatedAt: new Date().toISOString(),
    };
    ensureParentDir(sessionFile);
    writeFileSync(sessionFile, JSON.stringify(session, null, 2) + "\n");
  } catch { /* best-effort */ }
}

function restorePreviousSession() {
  try {
    const sessionFile = getSessionFilePath();
    if (!existsSync(sessionFile)) return;
    const prev = JSON.parse(readFileSync(sessionFile, "utf-8"));
    if (prev && prev.classification && prev.classification.role !== "APP Agent") {
      agentClassification = prev.classification;
    }
  } catch {
    // best-effort
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

const ERR_PARSE       = -32700;
const ERR_INVALID_REQ = -32600;
const ERR_NO_METHOD   = -32601;
const ERR_BAD_PARAMS  = -32602;
const ERR_INTERNAL    = -32603;
const ERR_ENGINE      = -32000;
const ERR_NOT_IDENTIFIED = -32001;

function jsonError(id, code, message) {
  return JSON.stringify({ id: id ?? null, error: { code, message } });
}

function jsonResult(id, result) {
  return JSON.stringify({ id, result });
}

function requireIdentified(id) {
  if (!agentIdentified) {
    return jsonError(id, ERR_NOT_IDENTIFIED,
      'Agent not identified. Call "identify" with {agent, version} before obfuscate/deobfuscate.');
  }
  return null;
}

// ---------------------------------------------------------------------------
// Agent classification from obfuscation text
// ---------------------------------------------------------------------------

function maybeClassify(text) {
  // Classify on the first 5 obfuscate calls — enough to see system prompt + context
  if (!classifyAgent || agentClassification?.confidencePct >= 70 || classificationTextSampled >= 5) return;
  classificationTextBuffer += " " + text;
  classificationTextSampled++;

  if (classificationTextSampled >= 2) {
    // Classify from accumulated text + agent label + tool sequence
    agentClassification = toolSequence.length > 0 && classifyAgentWithTools
      ? classifyAgentWithTools(agentLabel || "app-client", classificationTextBuffer, toolSequence)
      : classifyAgent(agentLabel || "app-client", classificationTextBuffer);

    if (agentClassification.confidencePct >= 40) {
      process.stderr.write(
        `[app-server] Agent classified: ${agentClassification.role} (${agentClassification.confidencePct}%)\n`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Injection scanning helper
// ---------------------------------------------------------------------------

function scanForInjections(text, direction) {
  if (!injectionDetector || !securityBus) return [];
  try {
    const events = direction === "request"
      ? injectionDetector.scanRequest(text)
      : injectionDetector.scanResponse(text);
    for (const evt of events) {
      evt.agentBuildId = agentBuildId;
      evt.agentLabel = agentLabel;
      evt.source = "app-server";
      securityBus.emit(evt);
    }
    return events;
  } catch { return []; }
}

// ---------------------------------------------------------------------------
// APP method handlers
// ---------------------------------------------------------------------------

function handleIdentify(id, params) {
  if (!params || typeof params.agent !== "string" || !params.agent.trim()) {
    return jsonError(id, ERR_BAD_PARAMS, 'Missing required param: agent (string)');
  }
  if (typeof params.version !== "string" || !params.version.trim()) {
    return jsonError(id, ERR_BAD_PARAMS, 'Missing required param: version (string)');
  }

  agentLabel = params.agent.trim();
  agentVersion = params.version.trim();
  agentChannel = (params.channel || "app").trim();
  agentBuildId = createHash("sha256")
    .update(agentLabel + ":" + agentVersion)
    .digest("hex")
    .slice(0, 16);
  agentIdentified = true;
  restorePreviousSession();

  process.stderr.write(
    `[app-server] Agent identified: ${agentLabel} v${agentVersion} (${agentChannel}) buildId=${agentBuildId}\n`
  );

  dumpSessionFile();

  return jsonResult(id, {
    ok: true,
    agent: agentLabel,
    buildId: agentBuildId,
    security: securityEnabled,
  });
}

async function handleObfuscate(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || typeof params.text !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: text");
  }

  const obf = resolvePartition(params);
  const text = params.text;

  // Classify agent from early obfuscation text (system prompt + context)
  maybeClassify(text);

  // Fingerprint system prompt (first obfuscation call per session)
  if (privacy.obfuscationCalls === 0) checkPromptFingerprint(text);

  // Injection scan on inbound text
  const injectionEvents = scanForInjections(text, "request");
  if (config.injectionDetection === "block" && injectionEvents.some(e => e.severity === "high")) {
    return jsonError(id, ERR_ENGINE,
      `Request blocked: injection detected (${injectionEvents[0].threatClass})`);
  }

  await warmPublicUrlCache(text);
  const out = obf.obfuscate(text);

  const categories = {};
  for (const e of out.entities) {
    categories[e.category] = (categories[e.category] || 0) + 1;
  }

  // Track per-agent privacy stats
  privacy.obfuscationCalls++;
  privacy.entitiesObfuscated += out.entities.length;
  for (const [cat, count] of Object.entries(categories)) {
    privacy.categoryCounts[cat] = (privacy.categoryCounts[cat] || 0) + count;
  }

  const result = {
    text: out.obfuscated,
    entityCount: out.entities.length,
    categories,
    modified: out.obfuscated !== text,
  };

  // Audit data
  const reqId = randomBytes(8).toString("hex");
  const audit = {
    requestId: reqId,
    inputChars: text.length,
    outputChars: out.obfuscated.length,
    proofIn: proofHash(text),
    proofOut: proofHash(out.obfuscated),
    chainHash: advanceChain({
      type: "obfuscate",
      categories,
      ts: Date.now(),
    }),
  };

  const maxFakes = config.auditMaxFakesSample || 3;
  audit.fakesSample = Object.values(out.mappingsUsed || {}).slice(0, maxFakes);
  if (injectionEvents.length > 0) audit.securityEvents = injectionEvents.length;
  result.audit = audit;

  dumpStats();
  return jsonResult(id, result);
}

function handleDeobfuscate(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || typeof params.text !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: text");
  }

  const obf = resolvePartition(params);
  const text = params.text;

  const deobResult = obf.deobfuscateWithStats
    ? obf.deobfuscateWithStats(text)
    : { text: obf.deobfuscate(text), replacementCount: 0, replacementsByCategory: {} };

  // Scan deobfuscated output for exfiltration markers
  const injectionEvents = scanForInjections(deobResult.text, "response");

  const stats = obf.getStats();

  // Track per-agent privacy stats
  const _deobCount = deobResult.replacementCount || 0;
  if (_deobCount > 0) {
    privacy.deobfuscationCalls++;
    privacy.replacementsDeobfuscated += _deobCount;
  }

  const result = {
    text: deobResult.text,
    replacementCount: _deobCount,
    replacementsByCategory: deobResult.replacementsByCategory || {},
    modified: deobResult.text !== text,
    storeSize: stats.storeMappings ?? 0,
  };

  const audit = {
    requestId: randomBytes(8).toString("hex"),
    proofIn: proofHash(text),
    proofOut: proofHash(deobResult.text),
    chainHash: advanceChain({
      type: "deobfuscate",
      replacementCount: result.replacementCount,
      ts: Date.now(),
    }),
  };
  if (injectionEvents.length > 0) audit.securityEvents = injectionEvents.length;
  result.audit = audit;

  dumpStats();
  return jsonResult(id, result);
}

// Write-path leak guard: does `text` still contain any fake token/component?
// Used by the client BEFORE a write reaches a backend. clean=false means the
// payload carries a value the model invented/recombined from fakes (never a
// real value) that deobfuscate() could not reverse. Scan-only; mutates nothing.
function handleVerifyClean(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || typeof params.text !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: text");
  }

  const obf = resolvePartition(params);
  const residual = typeof obf.findResidualFakes === "function"
    ? obf.findResidualFakes(params.text)
    : [];

  return jsonResult(id, { clean: residual.length === 0, residual: residual.slice(0, 50) });
}

async function handleBatch(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || !Array.isArray(params.operations)) {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: operations (array)");
  }

  const results = [];
  for (const op of params.operations) {
    const opParams = { ...op, partition: op.partition || params.partition };
    const obf = resolvePartition(opParams);

    if (op.direction === "obfuscate") {
      const injEvents = scanForInjections(op.text || "", "request");
      if (config.injectionDetection === "block" && injEvents.some(e => e.severity === "high")) {
        results.push({ error: `Blocked: injection detected (${injEvents[0].threatClass})` });
        continue;
      }
      await warmPublicUrlCache(op.text || "");
      const out = obf.obfuscate(op.text || "");
      const categories = {};
      for (const e of out.entities) {
        categories[e.category] = (categories[e.category] || 0) + 1;
      }
      results.push({
        text: out.obfuscated,
        entityCount: out.entities.length,
        categories,
        modified: out.obfuscated !== (op.text || ""),
      });
    } else if (op.direction === "deobfuscate") {
      const deob = obf.deobfuscateWithStats
        ? obf.deobfuscateWithStats(op.text || "")
        : { text: obf.deobfuscate(op.text || ""), replacementCount: 0 };
      results.push({
        text: deob.text,
        replacementCount: deob.replacementCount || 0,
        modified: deob.text !== (op.text || ""),
      });
    } else {
      results.push({ error: `Unknown direction: ${op.direction}` });
    }
  }

  return jsonResult(id, { results });
}

function handleReset(id, params) {
  const sessionStart = startTime;

  if (params?.partition) {
    const obf = partitionObfuscators.get(params.partition);
    if (obf) {
      const stats = obf.getStats();
      obf.reset();
      partitionObfuscators.delete(params.partition);
      return jsonResult(id, {
        ok: true,
        summary: {
          durationMs: Date.now() - sessionStart,
          storeMappings: stats.storeMappings ?? 0,
          detectionsByCategory: stats.detectionsByCategory ?? {},
        },
      });
    }
    return jsonResult(id, {
      ok: true,
      summary: { durationMs: 0, storeMappings: 0, detectionsByCategory: {} },
    });
  }

  // Reset all
  const stats = obfuscator.getStats();
  obfuscator.reset();
  chainHash = "0000000000000000";
  for (const [, obf] of partitionObfuscators) {
    obf.reset();
  }
  partitionObfuscators.clear();
  activePartition = null;

  dumpStats();
  return jsonResult(id, {
    ok: true,
    summary: {
      durationMs: Date.now() - sessionStart,
      storeMappings: stats.storeMappings ?? 0,
      detectionsByCategory: stats.detectionsByCategory ?? {},
    },
  });
}

function handleStats(id) {
  const obf = getObfuscator();
  const stats = obf.getStats();

  return jsonResult(id, {
    storeMappings: stats.storeMappings ?? 0,
    learnedEntities: stats.learnedEntities ?? 0,
    ruleHits: stats.ruleHits ?? {},
    detectionsByCategory: stats.detectionsByCategory ?? {},
    replacementsByCategory: stats.replacementsByCategory ?? {},
    audit: {
      totalObfuscations: stats.totalObfuscations ?? 0,
      totalDeobfuscations: stats.totalDeobfuscations ?? 0,
      sessionDurationMs: Date.now() - startTime,
    },
    engine: {
      name: "shroud",
      version: engineVersion,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
    },
  });
}

function handleHealth(id) {
  const obf = getObfuscator();
  const stats = obf.getStats();
  const uptimeSec = Math.floor((Date.now() - startTime) / 1000);
  const avgLatencyMs = requestCount > 0
    ? Math.round(totalProcessingMs / requestCount)
    : 0;

  return jsonResult(id, {
    ok: true,
    uptime: uptimeSec,
    pid: process.pid,
    requests: requestCount,
    avgLatencyMs,
    storeSize: stats.storeMappings ?? 0,
    memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
  });
}

function handleConfigure(id, params) {
  if (!params || typeof params.config !== "object") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: config (object)");
  }

  const appliedKeys = Object.keys(params.config);
  const merged = { ...pluginConfig, ...params.config };
  pluginConfig = merged;
  config = resolveConfig(merged);
  obfuscator = new Obfuscator(config);

  // Rebuild partition obfuscators with new config
  for (const [key] of partitionObfuscators) {
    partitionObfuscators.set(key, new Obfuscator(config));
  }

  return jsonResult(id, { ok: true, appliedKeys });
}

function handleShutdown(id) {
  dumpStats();
  dumpSessionFile();
  const response = jsonResult(id, { ok: true, flushed: true });
  process.stdout.write(response + "\n");
  process.exit(0);
}

function handleSetPartition(id, params) {
  if (!params || typeof params.id !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: id (string)");
  }

  activePartition = params.id;
  if (!partitionObfuscators.has(activePartition)) {
    partitionObfuscators.set(activePartition, new Obfuscator(config));
  }

  const obf = partitionObfuscators.get(activePartition);
  const stats = obf.getStats();

  return jsonResult(id, {
    ok: true,
    partition: activePartition,
    storeSize: stats.storeMappings ?? 0,
  });
}

function handleSecurity(id) {
  if (!securityBus) {
    return jsonResult(id, { enabled: false });
  }

  const events = securityBus.getEvents();
  const byThreatClass = {};
  for (const e of events) {
    byThreatClass[e.threatClass] = (byThreatClass[e.threatClass] || 0) + 1;
  }

  return jsonResult(id, {
    enabled: true,
    mode: config.injectionDetection || "flag",
    events: events.length,
    byThreatClass,
    agent: agentIdentified ? {
      label: agentLabel,
      buildId: agentBuildId,
      version: agentVersion,
      channel: agentChannel,
      requestCount,
    } : null,
    recentEvents: events.slice(-10).map(e => ({
      threatClass: e.threatClass,
      severity: e.severity,
      action: e.action,
      timestamp: e.timestamp,
      description: e.description?.slice(0, 200),
    })),
  });
}

function handleToolCall(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || typeof params.tool !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: tool (string)");
  }

  const toolName = params.tool;
  const toolArgs = params.args || {};
  const events = [];

  // Track in sequence
  toolSequence.push(toolName);

  // Tool guard: scan for dangerous commands
  if (scanToolCall && securityBus) {
    const guardResult = scanToolCall(toolName, toolArgs);
    if (guardResult.events.length > 0) {
      for (const evt of guardResult.events) {
        evt.agentBuildId = agentBuildId;
        evt.agentLabel = agentLabel;
        evt.source = "app-server";
        securityBus.emit(evt);
        events.push({
          threatClass: evt.threatClass,
          severity: evt.severity,
          action: evt.action,
          description: evt.description?.slice(0, 200),
        });
      }

      if (guardResult.shouldBlock && config.injectionDetection === "block") {
        return jsonResult(id, {
          allowed: false,
          blocked: true,
          reason: guardResult.events[0].description,
          events,
        });
      }
    }
  }

  // Injection scan on stringified args
  const argStr = JSON.stringify(toolArgs);
  const injEvents = scanForInjections(argStr, "request");
  for (const evt of injEvents) {
    events.push({
      threatClass: evt.threatClass,
      severity: evt.severity,
      action: evt.action,
    });
  }

  return jsonResult(id, {
    allowed: true,
    blocked: false,
    tool: toolName,
    sequenceLength: toolSequence.length,
    events: events.length > 0 ? events : undefined,
  });
}

function handleToolResult(id, params) {
  const gate = requireIdentified(id);
  if (gate) return gate;

  if (!params || typeof params.tool !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: tool (string)");
  }

  const toolName = params.tool;
  const resultText = params.result || "";
  const events = [];

  // Scan result for exfiltration markers
  if (typeof resultText === "string" && resultText.length > 0) {
    const injEvents = scanForInjections(resultText, "response");
    for (const evt of injEvents) {
      events.push({
        threatClass: evt.threatClass,
        severity: evt.severity,
        action: evt.action,
      });
    }
  }

  return jsonResult(id, {
    ok: true,
    tool: toolName,
    events: events.length > 0 ? events : undefined,
  });
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const METHODS = {
  identify: handleIdentify,
  obfuscate: handleObfuscate,
  deobfuscate: handleDeobfuscate,
  verify_clean: handleVerifyClean,
  batch: handleBatch,
  reset: handleReset,
  stats: handleStats,
  health: handleHealth,
  configure: handleConfigure,
  shutdown: handleShutdown,
  setPartition: handleSetPartition,
  security: handleSecurity,
  tool_call: handleToolCall,
  tool_result: handleToolResult,
};

async function dispatch(line) {
  if (!line.trim()) return;

  let req;
  try {
    req = JSON.parse(line);
  } catch (e) {
    process.stdout.write(jsonError(null, ERR_PARSE, `Parse error: ${e.message}`) + "\n");
    return;
  }

  const { id, method, params } = req;

  if (id === undefined || id === null || !method) {
    process.stdout.write(
      jsonError(id ?? null, ERR_INVALID_REQ, "Missing required field: id and method") + "\n"
    );
    return;
  }

  const handler = METHODS[method];
  if (!handler) {
    process.stdout.write(
      jsonError(id, ERR_NO_METHOD, `Method not found: ${method}`) + "\n"
    );
    return;
  }

  const t0 = Date.now();
  requestCount++;

  try {
    const response = await handler(id, params);
    // shutdown writes its own response and exits
    if (method !== "shutdown") {
      process.stdout.write(response + "\n");
    }
  } catch (e) {
    process.stdout.write(
      jsonError(id, ERR_ENGINE, `Engine error: ${e.message}`) + "\n"
    );
  }

  totalProcessingMs += Date.now() - t0;

  // Periodic session file dump
  if (requestCount % 10 === 0) dumpSessionFile();
}

// ---------------------------------------------------------------------------
// Heartbeat (stderr, every 30s)
// ---------------------------------------------------------------------------

const heartbeatInterval = setInterval(() => {
  try {
    const obf = getObfuscator();
    const stats = obf.getStats();
    const uptimeSec = Math.floor((Date.now() - startTime) / 1000);
    const avgLatencyMs = requestCount > 0
      ? Math.round(totalProcessingMs / requestCount)
      : 0;

    const hb = {
      heartbeat: true,
      pid: process.pid,
      uptime: uptimeSec,
      requests: requestCount,
      avgLatencyMs,
      storeSize: stats.storeMappings ?? 0,
      memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
      agent: agentLabel,
      security: securityEnabled,
    };
    process.stderr.write(JSON.stringify(hb) + "\n");
    dumpSessionFile();
  } catch { /* best-effort */ }
}, 30_000);

heartbeatInterval.unref();

// ---------------------------------------------------------------------------
// APP Initialization Handshake
// ---------------------------------------------------------------------------

const handshake = {
  app: "1.0",
  engine: "shroud",
  version: engineVersion,
  capabilities: [
    "obfuscate",
    "deobfuscate",
    "verify_clean",
    "batch",
    "stats",
    "health",
    "configure",
    "audit",
    "partitions",
    // Security capabilities (advertised even if not active, so clients know the protocol)
    "identify",
    "security",
    "tool_call",
    "tool_result",
  ],
  security: securityEnabled ? {
    injectionDetection: config.injectionDetection || "flag",
    scanResponses: config.injectionScanResponses ?? false,
    requireIdentify: true,
  } : null,
};

process.stderr.write(`[app-server] Starting APP server v${engineVersion}\n`);
process.stdout.write(JSON.stringify(handshake) + "\n");

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
let dispatchQueue = Promise.resolve();
rl.on("line", (line) => {
  dispatchQueue = dispatchQueue
    .then(() => dispatch(line))
    .catch((e) => {
      process.stdout.write(
        jsonError(null, ERR_ENGINE, `Engine error: ${e.message}`) + "\n"
      );
    });
});
rl.on("close", () => {
  clearInterval(heartbeatInterval);
  dumpStats();
  dumpSessionFile();
  process.exit(0);
});
