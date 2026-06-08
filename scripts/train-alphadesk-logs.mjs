#!/usr/bin/env node
/**
 * Import Alphadesk per-run JSONL logs into Shroud's behavioral profile store.
 *
 * Usage:
 *   node scripts/train-alphadesk-logs.mjs \
 *     /home/ka/alphadesk/data/logs/agents/runs \
 *     /home/ka/alphadesk/data/shroud/profiles
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = resolve(__dirname, "..");

const logsRoot = resolve(process.argv[2] || "/home/ka/alphadesk/data/logs/agents/runs");
const profileDir = resolve(process.argv[3] || "/home/ka/alphadesk/data/shroud/profiles");

const { VectorStore } = await import(pathToFileURL(join(repoRoot, "dist", "vector-store.js")).href);
const { TransformerScorer } = await import(pathToFileURL(join(repoRoot, "dist", "transformer", "scorer.js")).href);

const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)]+/g;
const MAX_URLS_PER_RUN = 50;
const MAX_RESULT_CHARS = 20000;
const MAX_SEQUENCE_TOOLS = Math.max(2, Number(process.env.SHROUD_TRAIN_MAX_SEQUENCE_TOOLS || 24));
const TRAINING_MAX_EPOCHS = Math.max(1, Number(process.env.SHROUD_TRAIN_MAX_EPOCHS || 3));
const TRAINING_MAX_SEQUENCES = Math.max(30, Number(process.env.SHROUD_TRAIN_MAX_SEQUENCES || 200));

function walkJsonl(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = statSync(path);
    if (st.isDirectory()) walkJsonl(path, out);
    else if (name.endsWith(".jsonl")) out.push(path);
  }
  return out;
}

function safeParse(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function extractUrls(value, out) {
  if (!value || out.size >= MAX_URLS_PER_RUN) return;
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const match of text.slice(0, MAX_RESULT_CHARS).matchAll(URL_RE)) {
    out.add(match[0]);
    if (out.size >= MAX_URLS_PER_RUN) break;
  }
}

function parseRun(path) {
  const lines = readFileSync(path, "utf-8").split(/\r?\n/).filter(Boolean);
  const sequence = [];
  const urls = new Set();
  let agentId = basename(resolve(path, ".."));
  let unhealthy = false;
  let startedAt = 0;

  for (const line of lines) {
    const event = safeParse(line);
    if (!event || typeof event !== "object") continue;

    if (event.event === "run_start") {
      agentId = event.agent_id || agentId;
      startedAt = Date.parse(event.ts || "") || startedAt;
      extractUrls(event.user_input, urls);
      continue;
    }

    if (event.event === "tool_call" && event.name) {
      sequence.push(String(event.name));
      extractUrls(event.input, urls);
      continue;
    }

    if (event.event === "tool_result") {
      extractUrls(event.result, urls);
      const resultText = typeof event.result === "string" ? event.result : JSON.stringify(event.result || "");
      if (/\b(blocked|injection_detected|credential access|exfiltration)\b/i.test(resultText)) {
        unhealthy = true;
      }
      continue;
    }

    if (event.event === "error" || event.event === "exception") unhealthy = true;
  }

  const originalToolCalls = sequence.length;
  const trainingSequence = sequence.length > MAX_SEQUENCE_TOOLS
    ? sequence.slice(-MAX_SEQUENCE_TOOLS)
    : sequence;

  return {
    agentId,
    sessionId: basename(path, ".jsonl"),
    sequence: trainingSequence,
    originalToolCalls,
    urls: [...urls],
    healthy: !unhealthy,
    startedAt,
  };
}

const files = walkJsonl(logsRoot).sort();
const vectorStore = new VectorStore(profileDir, 50000);

let imported = 0;
let skipped = 0;
let totalTools = 0;
let truncatedRuns = 0;
const perAgent = new Map();

for (const file of files) {
  const run = parseRun(file);
  if (run.sequence.length < 2) {
    skipped++;
    continue;
  }
  if (run.originalToolCalls > run.sequence.length) truncatedRuns++;
  vectorStore.recordWorkflow(
    run.agentId,
    run.sessionId,
    run.sequence,
    run.urls,
    run.healthy,
  );
  imported++;
  totalTools += run.originalToolCalls;
  perAgent.set(run.agentId, (perAgent.get(run.agentId) || 0) + 1);
}

vectorStore.flush();

const scorer = new TransformerScorer(profileDir, {
  anomalyThreshold: 0.85,
  windowSize: 10,
  minSequenceLength: 3,
  minSessionsToTrain: 30,
  trainIntervalSessions: 1,
  intentAttentionThreshold: 0.05,
  trainingMaxEpochs: TRAINING_MAX_EPOCHS,
  trainingMaxSequences: TRAINING_MAX_SEQUENCES,
});
const trainResult = await scorer.maybeRetrain(vectorStore);
scorer._saveModel?.();

const stats = scorer.getStats();
const topAgents = [...perAgent.entries()]
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .map(([agent, count]) => ({ agent, count }));

console.log(JSON.stringify({
  logsRoot,
  profileDir,
  scannedFiles: files.length,
  importedRuns: imported,
  skippedRuns: skipped,
  truncatedRuns,
  maxSequenceTools: MAX_SEQUENCE_TOOLS,
  totalToolCalls: totalTools,
  topAgents,
  transformer: {
    modelLoaded: stats.modelLoaded,
    trainingSessions: stats.trainingSessions,
    vocabSize: stats.vocabSize,
    lastLoss: stats.lastLoss,
    trainedThisRun: Boolean(trainResult),
    trainingMaxEpochs: TRAINING_MAX_EPOCHS,
    trainingMaxSequences: TRAINING_MAX_SEQUENCES,
  },
}, null, 2));
