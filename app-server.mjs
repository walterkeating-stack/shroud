#!/usr/bin/env node
/**
 * APP Server — Agent Privacy Protocol reference implementation.
 *
 * Implements APP-RFC-0001 Level 3 (Enterprise) compliance.
 * Wraps the Shroud obfuscation engine and exposes all APP methods
 * over newline-delimited JSON-RPC on stdio.
 *
 * Usage:
 *   node app-server.mjs [dist-path]
 *
 * Environment:
 *   SHROUD_PLUGIN_CONFIG   JSON config for the engine
 *   SHROUD_STORE_FILE      Persistent store file path
 *   SHROUD_STATS_FILE      Stats dump file path
 *   SHROUD_APP_EVENTS_FILE JSONL file for APP-side event export
 *   SHROUD_APP_SESSIONS_FILE JSON file for APP-side agent session state
 */

import { createHash, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { resolve, dirname } from "node:path";
import { writeFileSync, readFileSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer as createNetServer } from "node:net";

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

const STATS_FILE = process.env.SHROUD_STATS_FILE || "/tmp/shroud-stats.json";
const STORE_FILE = process.env.SHROUD_STORE_FILE || "";
const APP_EVENTS_FILE = process.env.SHROUD_APP_EVENTS_FILE || "/tmp/shroud-app-events.jsonl";
const APP_SESSIONS_FILE = process.env.SHROUD_APP_SESSIONS_FILE || "/tmp/shroud-app-sessions.json";

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
const toolSequence = [];
const privacy = {
  obfuscationCalls: 0,
  deobfuscationCalls: 0,
  entitiesObfuscated: 0,
  replacementsDeobfuscated: 0,
  categoryCounts: {},
};

let agentIdentified = false;
let agentLabel = null;
let agentBuildId = null;
let agentVersion = null;
let agentChannel = null;

// ---------------------------------------------------------------------------
// Stats dump helper
// ---------------------------------------------------------------------------

function dumpStats() {
  try {
    const stats = getObfuscator().getStats();
    stats.updatedAt = new Date().toISOString();
    stats.pid = process.pid;
    writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2) + "\n");
  } catch { /* best-effort */ }
}

function dumpSessionFile() {
  if (!agentIdentified) return;
  try {
    const session = {
      agentLabel,
      agentBuildId,
      agentVersion,
      channel: agentChannel,
      source: "app-server",
      pid: process.pid,
      requestCount,
      uptimeMs: Date.now() - startTime,
      securityEvents: 0,
      storeSize: getObfuscator().getStats().storeMappings ?? 0,
      classification: {
        role: "APP Agent",
        confidencePct: 100,
        confidence: "high",
        colour: "#06b6d4",
        signals: ["app-server"],
      },
      toolSequence: toolSequence.slice(-20),
      privacy,
      eventsFile: APP_EVENTS_FILE,
      updatedAt: new Date().toISOString(),
    };
    writeFileSync(APP_SESSIONS_FILE, JSON.stringify(session, null, 2) + "\n");
  } catch { /* best-effort */ }
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

function jsonError(id, code, message) {
  return JSON.stringify({ id: id ?? null, error: { code, message } });
}

function jsonResult(id, result) {
  return JSON.stringify({ id, result });
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
  agentChannel = typeof params.channel === "string" && params.channel.trim() ? params.channel.trim() : "app";
  agentBuildId = createHash("sha256")
    .update(agentLabel + ":" + agentVersion)
    .digest("hex")
    .slice(0, 16);
  agentIdentified = true;

  process.stderr.write(
    `[app-server] Agent identified: ${agentLabel} v${agentVersion} (${agentChannel}) buildId=${agentBuildId}\n`
  );

  dumpSessionFile();

  return jsonResult(id, {
    ok: true,
    agent: agentLabel,
    buildId: agentBuildId,
    security: false,
  });
}

function handleObfuscate(id, params) {
  if (!params || typeof params.text !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: text");
  }

  const obf = resolvePartition(params);
  const text = params.text;
  const out = obf.obfuscate(text);

  const categories = {};
  for (const e of out.entities) {
    categories[e.category] = (categories[e.category] || 0) + 1;
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
  result.audit = audit;

  privacy.obfuscationCalls++;
  privacy.entitiesObfuscated += out.entities.length;
  for (const [cat, count] of Object.entries(categories)) {
    privacy.categoryCounts[cat] = (privacy.categoryCounts[cat] || 0) + count;
  }

  dumpStats();
  return jsonResult(id, result);
}

function handleDeobfuscate(id, params) {
  if (!params || typeof params.text !== "string") {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: text");
  }

  const obf = resolvePartition(params);
  const text = params.text;

  const deobResult = obf.deobfuscateWithStats
    ? obf.deobfuscateWithStats(text)
    : { text: obf.deobfuscate(text), replacementCount: 0, replacementsByCategory: {} };

  const stats = obf.getStats();

  const result = {
    text: deobResult.text,
    replacementCount: deobResult.replacementCount || 0,
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
  result.audit = audit;

  if ((deobResult.replacementCount || 0) > 0) {
    privacy.deobfuscationCalls++;
    privacy.replacementsDeobfuscated += deobResult.replacementCount || 0;
  }

  dumpStats();
  return jsonResult(id, result);
}

function handleBatch(id, params) {
  if (!params || !Array.isArray(params.operations)) {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: operations (array)");
  }

  const results = [];
  for (const op of params.operations) {
    const opParams = { ...op, partition: op.partition || params.partition };
    const obf = resolvePartition(opParams);

    if (op.direction === "obfuscate") {
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

function handleSecurity(id) {
  return jsonResult(id, {
    enabled: false,
    mode: "off",
    events: 0,
    byThreatClass: {},
    agent: agentIdentified ? {
      label: agentLabel,
      buildId: agentBuildId,
      version: agentVersion,
      channel: agentChannel,
      requestCount,
    } : null,
    recentEvents: [],
  });
}

function handleToolCall(id, params) {
  if (!params || typeof params.tool !== "string" || !params.tool.trim()) {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: tool (string)");
  }

  toolSequence.push(params.tool.trim());

  return jsonResult(id, {
    blocked: false,
    reason: null,
    sequenceLength: toolSequence.length,
    events: [],
    securityEnabled: false,
  });
}

function handleToolResult(id, params) {
  if (!params || typeof params.tool !== "string" || !params.tool.trim()) {
    return jsonError(id, ERR_BAD_PARAMS, "Missing required param: tool (string)");
  }

  return jsonResult(id, {
    ok: true,
    recorded: true,
  });
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

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const METHODS = {
  identify: handleIdentify,
  obfuscate: handleObfuscate,
  deobfuscate: handleDeobfuscate,
  batch: handleBatch,
  reset: handleReset,
  stats: handleStats,
  health: handleHealth,
  security: handleSecurity,
  tool_call: handleToolCall,
  tool_result: handleToolResult,
  configure: handleConfigure,
  shutdown: handleShutdown,
  setPartition: handleSetPartition,
};

function dispatch(line, writeFn) {
  if (!line.trim()) return;
  const write = writeFn || ((s) => process.stdout.write(s));

  let req;
  try {
    req = JSON.parse(line);
  } catch (e) {
    write(jsonError(null, ERR_PARSE, `Parse error: ${e.message}`) + "\n");
    return;
  }

  const { id, method, params } = req;

  if (id === undefined || id === null || !method) {
    write(
      jsonError(id ?? null, ERR_INVALID_REQ, "Missing required field: id and method") + "\n"
    );
    return;
  }

  const handler = METHODS[method];
  if (!handler) {
    write(
      jsonError(id, ERR_NO_METHOD, `Method not found: ${method}`) + "\n"
    );
    return;
  }

  const t0 = Date.now();
  requestCount++;

  try {
    const response = handler(id, params);
    // shutdown writes its own response and exits
    if (method !== "shutdown") {
      write(response + "\n");
      dumpSessionFile();
    }
  } catch (e) {
    write(
      jsonError(id, ERR_ENGINE, `Engine error: ${e.message}`) + "\n"
    );
  }

  totalProcessingMs += Date.now() - t0;
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
    };
    process.stderr.write(JSON.stringify(hb) + "\n");
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
    "identify",
    "obfuscate",
    "deobfuscate",
    "batch",
    "stats",
    "health",
    "configure",
    "security",
    "tool_call",
    "tool_result",
    "audit",
    "partitions",
  ],
  security: null,
};

process.stderr.write(`[app-server] Starting APP server v${engineVersion}\n`);

// ---------------------------------------------------------------------------
// Socket listener mode (--listen <path>)
// ---------------------------------------------------------------------------

const listenFlag = process.argv.indexOf("--listen");
const SOCKET_PATH = listenFlag !== -1 ? (process.argv[listenFlag + 1] || "/tmp/shroud-app.sock") : null;

if (SOCKET_PATH) {
  // Remove stale socket file
  try { unlinkSync(SOCKET_PATH); } catch {}

  let socketClients = 0;
  const socketServer = createNetServer((conn) => {
    socketClients++;
    const clientId = socketClients;
    process.stderr.write(`[app-server] Socket client #${clientId} connected\n`);

    // Send handshake to this client
    conn.write(JSON.stringify(handshake) + "\n");

    let connected = true;
    const connRl = createInterface({ input: conn, crlfDelay: Infinity });
    const connWrite = (s) => { if (connected) try { conn.write(s); } catch {} };

    connRl.on("line", (line) => dispatch(line, connWrite));
    connRl.on("error", () => {});
    conn.on("error", () => { connected = false; });
    conn.on("close", () => {
      connected = false;
      process.stderr.write(`[app-server] Socket client #${clientId} disconnected\n`);
    });
  });

  socketServer.listen(SOCKET_PATH, () => {
    process.stderr.write(`[app-server] Listening on socket: ${SOCKET_PATH}\n`);
  });

  socketServer.on("error", (err) => {
    process.stderr.write(`[app-server] Socket error: ${err.message}\n`);
    process.exit(1);
  });

  // Also still serve stdin for backwards compat
  process.stdout.write(JSON.stringify(handshake) + "\n");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => dispatch(line));
  rl.on("close", () => {
    try { unlinkSync(SOCKET_PATH); } catch {}
    socketServer.close();
    clearInterval(heartbeatInterval);
    dumpStats();
    dumpSessionFile();
    process.exit(0);
  });

  // Cleanup socket on exit
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      try { unlinkSync(SOCKET_PATH); } catch {}
      socketServer.close();
      clearInterval(heartbeatInterval);
      dumpStats();
      dumpSessionFile();
      process.exit(0);
    });
  }
} else {
  // ---------------------------------------------------------------------------
  // Default: stdin/stdout mode
  // ---------------------------------------------------------------------------

  process.stdout.write(JSON.stringify(handshake) + "\n");

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => dispatch(line));
  rl.on("close", () => {
    clearInterval(heartbeatInterval);
    dumpStats();
    dumpSessionFile();
    process.exit(0);
  });
}
