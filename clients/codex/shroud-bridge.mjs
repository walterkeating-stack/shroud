#!/usr/bin/env node
/**
 * Codex history bridge for Shroud.
 *
 * Codex CLI does not emit APP telemetry for ordinary turns unless it calls
 * Shroud MCP tools. This bridge watches Codex's local history file on the
 * host, synthesizes a stable session snapshot, and writes it into the shared
 * OpenClaw state directory so session/call counters stay current.
 */

import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { applyCodexBridgeEnv } from "./bridge-env.mjs";
import { resolveExternalAgentConfig } from "../shared/agent-config.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const telemetry = await import(pathToFileURL(resolve(__dirname, "../../dist/codex-telemetry.js")).href);
applyCodexBridgeEnv(process.env);

const {
  computeExternalAgentBuildId,
  loadCodexHistorySummary,
  resolveCodexHistoryFile,
} = telemetry;

const AGENT = resolveExternalAgentConfig({
  agentLabel: "codex",
  agentVersion: "1.0.0",
  agentChannel: "codex-cli",
  agentSlug: "codex-cli",
});

const BRIDGE_SESSION_FILE = AGENT.sessionFile;
const MCP_SESSION_FILE = join(AGENT.stateDir, "shroud-codex-mcp-sessions.json");
const PID_FILE = join(AGENT.stateDir, "shroud-codex-bridge.pid");
const POLL_MS = Math.max(1000, Number(process.env.SHROUD_CODEX_BRIDGE_POLL_MS || 5000));
const startTime = Date.now();
let lastSerialized = "";
let warnedMissingHistory = false;
let ownsPidFile = false;

function log(message) {
  process.stderr.write(`[shroud-codex-bridge] ${message}\n`);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return null;
  }
}

function mergeCategoryCounts(...countsList) {
  const merged = {};
  for (const counts of countsList) {
    if (!counts || typeof counts !== "object") continue;
    for (const [key, value] of Object.entries(counts)) {
      merged[key] = Math.max(Number(merged[key] || 0), Number(value || 0));
    }
  }
  return merged;
}

function pidIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function tryAcquirePidFile() {
  try {
    writeFileSync(PID_FILE, `${process.pid}\n`, { flag: "wx" });
    ownsPidFile = true;
    return true;
  } catch {
    try {
      const existingPid = Number.parseInt(readFileSync(PID_FILE, "utf-8").trim(), 10);
      if (pidIsAlive(existingPid)) return false;
    } catch {}
    try {
      unlinkSync(PID_FILE);
    } catch {}
    try {
      writeFileSync(PID_FILE, `${process.pid}\n`, { flag: "wx" });
      ownsPidFile = true;
      return true;
    } catch {
      return false;
    }
  }
}

function cleanupPidFile() {
  if (!ownsPidFile) return;
  try {
    const raw = readFileSync(PID_FILE, "utf-8").trim();
    if (raw === String(process.pid)) unlinkSync(PID_FILE);
  } catch {}
  ownsPidFile = false;
}

function buildSnapshot() {
  const historyFile = resolveCodexHistoryFile();
  const historySummary = loadCodexHistorySummary(historyFile);
  const rawExistingBridge = readJson(BRIDGE_SESSION_FILE);
  const rawExistingMcp = readJson(MCP_SESSION_FILE);
  const existingBridge = rawExistingBridge || {};
  const existingMcp = rawExistingMcp || {};

  if (!historySummary || historySummary.promptCount <= 0) {
    if (!warnedMissingHistory) {
      warnedMissingHistory = true;
      log(`waiting for Codex history at ${historyFile}`);
    }
    if (!rawExistingBridge && !rawExistingMcp) return null;
  } else {
    warnedMissingHistory = false;
  }

  const agentLabel = String(existingMcp.agentLabel || existingBridge.agentLabel || AGENT.agentLabel || "codex");
  const agentVersion = String(existingMcp.agentVersion || existingBridge.agentVersion || AGENT.agentVersion || "1.0.0");
  const updatedAtMs = Math.max(
    Number(historySummary?.lastPromptAtMs || 0),
    Date.parse(String(existingBridge.updatedAt || "")) || 0,
    Date.parse(String(existingMcp.updatedAt || "")) || 0,
  );

  return {
    agentLabel,
    agentBuildId: computeExternalAgentBuildId(agentLabel, agentVersion),
    agentVersion,
    channel: AGENT.agentChannel,
    source: "codex-history-bridge",
    pid: process.pid,
    requestCount: Math.max(
      Number(historySummary?.promptCount || 0),
      Number(existingBridge.requestCount || 0),
      Number(existingMcp.requestCount || 0),
    ),
    sessionCount: Math.max(
      Number(historySummary?.sessionCount || 0),
      Number(existingBridge.sessionCount || 0),
      Number(existingMcp.sessionCount || 0),
    ),
    uptimeMs: Date.now() - startTime,
    securityEvents: Math.max(
      Number(existingBridge.securityEvents || 0),
      Number(existingMcp.securityEvents || 0),
    ),
    storeSize: Math.max(
      Number(existingBridge.storeSize || 0),
      Number(existingMcp.storeSize || 0),
    ),
    toolSequence: Array.isArray(existingMcp.toolSequence)
      ? existingMcp.toolSequence
      : Array.isArray(existingBridge.toolSequence)
        ? existingBridge.toolSequence
        : [],
    privacy: {
      obfuscationCalls: Math.max(
        Number(existingBridge?.privacy?.obfuscationCalls || 0),
        Number(existingMcp?.privacy?.obfuscationCalls || 0),
      ),
      deobfuscationCalls: Math.max(
        Number(existingBridge?.privacy?.deobfuscationCalls || 0),
        Number(existingMcp?.privacy?.deobfuscationCalls || 0),
      ),
      entitiesObfuscated: Math.max(
        Number(existingBridge?.privacy?.entitiesObfuscated || 0),
        Number(existingMcp?.privacy?.entitiesObfuscated || 0),
      ),
      replacementsDeobfuscated: Math.max(
        Number(existingBridge?.privacy?.replacementsDeobfuscated || 0),
        Number(existingMcp?.privacy?.replacementsDeobfuscated || 0),
      ),
      categoryCounts: mergeCategoryCounts(
        existingBridge?.privacy?.categoryCounts,
        existingMcp?.privacy?.categoryCounts,
      ),
    },
    classification: existingMcp.classification || existingBridge.classification || {
      role: "APP Agent",
      confidencePct: 100,
      confidence: "high",
      colour: "#06b6d4",
      signals: ["codex-history-bridge"],
    },
    promptFingerprint: existingMcp.promptFingerprint || existingBridge.promptFingerprint || null,
    updatedAt: new Date(updatedAtMs || Date.now()).toISOString(),
  };
}

function flushSnapshot() {
  const snapshot = buildSnapshot();
  if (!snapshot) return;
  const serialized = JSON.stringify(snapshot, null, 2);
  if (serialized === lastSerialized) return;
  writeFileSync(BRIDGE_SESSION_FILE, `${serialized}\n`);
  lastSerialized = serialized;
}

if (!tryAcquirePidFile()) {
  log(`already running via ${PID_FILE}`);
  process.exit(0);
}

flushSnapshot();
setInterval(flushSnapshot, POLL_MS);

process.on("exit", cleanupPidFile);
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));

log(`watching ${resolveCodexHistoryFile()} -> ${BRIDGE_SESSION_FILE}`);
