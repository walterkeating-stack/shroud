/**
 * Persisted vector store — workflow fingerprinting, clustering,
 * cross-session URL correlation, and per-agent lifetime baselines.
 *
 * Stores tool-call sequences as n-gram embedded vectors on disk.
 * Clusters healthy workflows into known regions. Correlates across
 * sessions to identify malicious URLs from behavioral patterns alone.
 *
 * Persistence: single JSON file at {profileDir}/vector-store.json.
 * Loaded on startup, flushed on 30s/5-call/SIGTERM cadence.
 *
 * Zero external dependencies.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { SequenceEmbedder } from "./detectors/sequence-embedder.js";
import type { SecurityEvent, SecuritySeverity } from "./security-event.js";
import { ThreatClass } from "./security-event.js";
import type { RunningStats } from "./profiler-types.js";
import type { TransitionStatsMap } from "./causal-coherence.js";

// ─── Types ───

/** A stored workflow vector with metadata. */
export interface WorkflowEntry {
  id: string;
  agentBuildId: string;
  sessionId: string;
  sequence: string[];
  vector: number[];
  timestamp: number;
  urls: string[];
  healthy: boolean;
}

/** A workflow cluster (incremental centroid). */
export interface WorkflowCluster {
  id: string;
  label: string;
  centroid: number[];
  count: number;
  radius: number;
  agentBuildIds: string[];
}

/** Cross-session URL correlation fingerprint entry. */
export interface UrlSessionFingerprint {
  sessionId: string;
  agentBuildId: string;
  sequenceAfterUrl: string[];
  vector: number[];
  timestamp: number;
  flagged: boolean;
}

/** Cross-session URL correlation. */
export interface UrlFingerprint {
  url: string;
  sessionFingerprints: UrlSessionFingerprint[];
  malicious: boolean;
  confidence: number;
}

/** Snapshot of agent profile at a point in time. */
export interface EvolutionSnapshot {
  sessionCount: number;
  timestamp: number;
  clusterCount: number;
  centroidShift: number;
  maturity: "learning" | "reliable" | "mature";
  /** Byte offset into the agent's .evolution.bin file where this centroid starts.
   *  Each centroid is 256 × 8 = 2048 bytes (Float64). */
  centroidOffset: number;
  /** Cluster positions at this snapshot — centroid + radius + label for each cluster
   *  the agent belongs to. Stored inline (small) rather than in binary (rarely >10). */
  clusterPositions: Array<{
    clusterId: string;
    label: string;
    centroidOffset: number;  // offset into same .evolution.bin
    radius: number;
    memberCount: number;
  }>;
}

/** Record of a novel sequence and its outcome. */
export interface NoveltyLogEntry {
  timestamp: number;
  sequenceHash: string;
  toolNames: string[];
  outcome: "absorbed" | "confirmed" | "pending";
  resolvedAt?: number;
}

/** Per-agent lifetime vector baseline with evolution tracking. */
export interface AgentVectorBaseline {
  agentBuildId: string;
  workflowVectors: number[][];
  centroid: number[];
  count: number;
  radius: number;
  maturity: "learning" | "reliable" | "mature";
  transitionStats: TransitionStatsMap;
  evolution: {
    snapshots: EvolutionSnapshot[];
    noveltyLog: NoveltyLogEntry[];
    transitionMaturity: Record<string, { n: number; stableAt?: number }>;
  };
}

/** Full persisted state. */
interface VectorStoreData {
  version: number;
  workflows: WorkflowEntry[];
  clusters: WorkflowCluster[];
  urlFingerprints: UrlFingerprint[];
  agentBaselines: Record<string, AgentVectorBaseline>;
  lastFlushed: number;
}

// ─── Vector math helpers ───

function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (denom === 0) return 0;
  return Math.max(0, Math.min(1, dot / denom));
}

function addVectors(a: number[], b: number[]): number[] {
  return a.map((v, i) => v + (b[i] || 0));
}

function scaleVector(v: number[], s: number): number[] {
  return v.map(x => x * s);
}

// ─── Vector store ───

export class VectorStore {
  private _profileDir: string;
  private _maxWorkflows: number;
  private _embedder: SequenceEmbedder;

  private _workflows: WorkflowEntry[] = [];
  private _clusters: WorkflowCluster[] = [];
  private _urlFingerprints: Map<string, UrlFingerprint> = new Map();
  private _agentBaselines: Map<string, AgentVectorBaseline> = new Map();
  private _dirty = false;

  constructor(profileDir: string, maxWorkflows = 10000) {
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
    this._maxWorkflows = maxWorkflows;
    this._embedder = new SequenceEmbedder(256);
    this._load();
  }

  // ─── Workflow management ───

  /**
   * Record a completed session's tool-call sequence.
   * Embeds it, classifies against clusters, updates agent baseline.
   */
  recordWorkflow(
    agentBuildId: string,
    sessionId: string,
    sequence: string[],
    urls: string[],
    healthy: boolean,
  ): { clusterId: string | null; novel: boolean; similarity: number } {
    if (sequence.length === 0) return { clusterId: null, novel: false, similarity: 1 };

    const vector = Array.from(this._embedder.embedSequence(sequence));
    const id = createHash("sha256")
      .update(`${agentBuildId}:${sequence.join(",")}:${sessionId}`)
      .digest("hex")
      .slice(0, 16);

    const entry: WorkflowEntry = {
      id, agentBuildId, sessionId, sequence, vector, timestamp: Date.now(), urls, healthy,
    };

    this._workflows.push(entry);
    this._evictWorkflows();

    // Classify against clusters
    const { clusterId, similarity } = this._classifyWorkflow(vector, agentBuildId);

    // Update agent baseline
    this._updateAgentBaseline(agentBuildId, vector, sequence, healthy, clusterId === null);

    this._dirty = true;
    return { clusterId, novel: clusterId === null, similarity };
  }

  /** Classify a workflow vector against existing clusters. */
  private _classifyWorkflow(
    vector: number[],
    agentBuildId: string,
  ): { clusterId: string | null; similarity: number } {
    let bestCluster: WorkflowCluster | null = null;
    let bestSimilarity = 0;

    for (const cluster of this._clusters) {
      const sim = cosineSimilarity(vector, cluster.centroid);
      if (sim > bestSimilarity) {
        bestSimilarity = sim;
        bestCluster = cluster;
      }
    }

    if (bestCluster && bestSimilarity > 0.7) {
      // Merge into existing cluster (update centroid as running average)
      const n = bestCluster.count;
      bestCluster.centroid = scaleVector(
        addVectors(scaleVector(bestCluster.centroid, n), vector),
        1 / (n + 1),
      );
      bestCluster.count += 1;
      const dist = 1 - bestSimilarity;
      if (dist > bestCluster.radius) bestCluster.radius = dist;
      if (!bestCluster.agentBuildIds.includes(agentBuildId)) {
        bestCluster.agentBuildIds.push(agentBuildId);
      }
      return { clusterId: bestCluster.id, similarity: bestSimilarity };
    }

    // Create new cluster
    const newCluster: WorkflowCluster = {
      id: createHash("sha256").update(`cluster-${Date.now()}-${Math.random()}`).digest("hex").slice(0, 12),
      label: this._deriveClusterLabel(vector),
      centroid: [...vector],
      count: 1,
      radius: 0,
      agentBuildIds: [agentBuildId],
    };
    this._clusters.push(newCluster);
    return { clusterId: newCluster.id, similarity: bestSimilarity };
  }

  /**
   * Derive a semantic behavior label from tool frequency patterns.
   * Maps tool combinations to human-readable workflow archetypes.
   */
  private _deriveClusterLabel(_vector: number[]): string {
    const recent = this._workflows.slice(-10);
    const toolCounts = new Map<string, number>();
    let total = 0;
    for (const w of recent) {
      for (const t of w.sequence) {
        toolCounts.set(t, (toolCounts.get(t) || 0) + 1);
        total++;
      }
    }
    if (total === 0) return "unknown";

    const pct = (tool: string) => (toolCounts.get(tool) || 0) / total;
    const has = (tool: string) => toolCounts.has(tool);

    // Research: heavy on read + web_fetch, light on write/edit
    if ((pct("read") + pct("read_file")) > 0.3 &&
        (has("web_fetch") || has("fetch") || has("browser")) &&
        !has("edit") && !has("write") && !has("write_file")) {
      return "research";
    }

    // Coding: read + edit/write + exec cycle
    if ((has("edit") || has("write") || has("write_file")) &&
        (has("exec") || has("bash") || has("code_execution"))) {
      if (pct("exec") + pct("bash") + pct("code_execution") > 0.3) return "testing";
      return "coding";
    }

    // Communication: message/send heavy
    if (pct("message") + pct("sessions_send") + pct("slack_send") > 0.3) {
      return "communication";
    }

    // Exploration: mostly reading, no writing
    if ((pct("read") + pct("read_file")) > 0.5 && !has("edit") && !has("write")) {
      return "exploration";
    }

    // Automation: exec/bash dominant
    if (pct("exec") + pct("bash") + pct("code_execution") > 0.5) {
      return "automation";
    }

    // Data gathering: web_fetch dominant
    if (pct("web_fetch") + pct("fetch") + pct("browser") > 0.3) {
      return "data-gathering";
    }

    // Memory operations
    if (pct("memory_search") + pct("memory_get") > 0.3) {
      return "memory-recall";
    }

    // Delegation: spawning/sending to other agents
    if (has("sessions_spawn") || pct("sessions_send") > 0.2) {
      return "orchestration";
    }

    // Fallback: dominant tool name
    let dominant = "unknown";
    let maxCount = 0;
    for (const [tool, count] of toolCounts) {
      if (count > maxCount) { dominant = tool; maxCount = count; }
    }
    return dominant;
  }

  // ─── Binary evolution file ───

  /** Path to an agent's binary evolution file. */
  private _evolutionBinPath(agentBuildId: string): string {
    const safe = agentBuildId.replace(/[^a-zA-Z0-9_-]/g, "");
    return join(this._profileDir, `${safe}.evolution.bin`);
  }

  /**
   * Append a 256-dim vector to a binary file as raw Float64.
   * Returns the byte offset where the vector starts.
   * Each vector = 256 × 8 = 2048 bytes.
   */
  private _appendVectorToBin(filePath: string, vector: number[]): number {
    try {
      mkdirSync(this._profileDir, { recursive: true });
      let offset = 0;
      try {
        offset = statSync(filePath).size;
      } catch { /* file doesn't exist yet */ }
      const buf = Buffer.alloc(256 * 8);
      for (let i = 0; i < 256; i++) {
        buf.writeDoubleBE(vector[i] || 0, i * 8);
      }
      appendFileSync(filePath, buf);
      return offset;
    } catch {
      return -1; // Best-effort — don't crash if disk write fails
    }
  }

  /**
   * Read a 256-dim vector from a binary evolution file at the given offset.
   * Returns null if the file doesn't exist or offset is invalid.
   */
  readVectorFromBin(agentBuildId: string, offset: number): number[] | null {
    if (offset < 0) return null;
    const filePath = this._evolutionBinPath(agentBuildId);
    try {
      const buf = readFileSync(filePath);
      if (offset + 2048 > buf.length) return null;
      const vec: number[] = [];
      for (let i = 0; i < 256; i++) {
        vec.push(buf.readDoubleBE(offset + i * 8));
      }
      return vec;
    } catch {
      return null;
    }
  }

  /**
   * Read all centroid snapshots for an agent — returns the full centroid
   * trajectory through vector space for timeline replay.
   */
  readEvolutionTrajectory(agentBuildId: string): Array<{
    timestamp: number;
    sessionCount: number;
    maturity: string;
    centroid: number[];
    centroidShift: number;
    clusters: Array<{ label: string; centroid: number[]; radius: number; memberCount: number }>;
  }> {
    const baseline = this._agentBaselines.get(agentBuildId);
    if (!baseline) return [];

    return baseline.evolution.snapshots.map(snap => ({
      timestamp: snap.timestamp,
      sessionCount: snap.sessionCount,
      maturity: snap.maturity,
      centroidShift: snap.centroidShift,
      centroid: this.readVectorFromBin(agentBuildId, snap.centroidOffset) || [],
      clusters: (snap.clusterPositions || []).map(cp => ({
        label: cp.label,
        centroid: this.readVectorFromBin(agentBuildId, cp.centroidOffset) || [],
        radius: cp.radius,
        memberCount: cp.memberCount,
      })),
    }));
  }

  // ─── Agent baselines ───

  private _updateAgentBaseline(
    agentBuildId: string,
    vector: number[],
    sequence: string[],
    healthy: boolean,
    novel: boolean,
  ): void {
    let baseline = this._agentBaselines.get(agentBuildId);
    if (!baseline) {
      baseline = {
        agentBuildId,
        workflowVectors: [],
        centroid: new Array(256).fill(0),
        count: 0,
        radius: 0,
        maturity: "learning",
        transitionStats: {},
        evolution: { snapshots: [], noveltyLog: [], transitionMaturity: {} },
      };
      this._agentBaselines.set(agentBuildId, baseline);
    }

    if (healthy) {
      // Store the previous centroid for shift measurement
      const prevCentroid = [...baseline.centroid];

      baseline.workflowVectors.push(vector);
      // Cap stored vectors (keep most recent 200)
      if (baseline.workflowVectors.length > 200) {
        baseline.workflowVectors = baseline.workflowVectors.slice(-200);
      }
      const n = baseline.count;
      baseline.centroid = scaleVector(
        addVectors(scaleVector(baseline.centroid, n), vector),
        1 / (n + 1),
      );
      baseline.count += 1;
      const dist = 1 - cosineSimilarity(vector, baseline.centroid);
      if (dist > baseline.radius) baseline.radius = dist;

      // Update maturity
      if (baseline.count >= 50) baseline.maturity = "mature";
      else if (baseline.count >= 5) baseline.maturity = "reliable";
      else baseline.maturity = "learning";

      // Record evolution snapshot every 5 sessions
      if (baseline.count % 5 === 0 || baseline.count <= 5) {
        const centroidShift = n > 0 ? 1 - cosineSimilarity(prevCentroid, baseline.centroid) : 0;
        const agentClusters = this._clusters.filter(c => c.agentBuildIds.includes(agentBuildId));

        // Write centroid + cluster centroids to binary evolution file
        const binFile = this._evolutionBinPath(agentBuildId);
        const centroidOffset = this._appendVectorToBin(binFile, baseline.centroid);
        const clusterPositions = agentClusters.map(c => ({
          clusterId: c.id,
          label: c.label,
          centroidOffset: this._appendVectorToBin(binFile, c.centroid),
          radius: c.radius,
          memberCount: c.count,
        }));

        baseline.evolution.snapshots.push({
          sessionCount: baseline.count,
          timestamp: Date.now(),
          clusterCount: agentClusters.length,
          centroidShift,
          maturity: baseline.maturity,
          centroidOffset,
          clusterPositions,
        });
        // Cap snapshots at 100
        if (baseline.evolution.snapshots.length > 100) {
          baseline.evolution.snapshots = baseline.evolution.snapshots.slice(-100);
        }
      }
    }

    // Log novelty
    if (novel) {
      const seqHash = createHash("sha256").update(sequence.join(",")).digest("hex").slice(0, 12);
      baseline.evolution.noveltyLog.push({
        timestamp: Date.now(),
        sequenceHash: seqHash,
        toolNames: sequence,
        outcome: "pending",
      });
      // Cap novelty log at 200
      if (baseline.evolution.noveltyLog.length > 200) {
        baseline.evolution.noveltyLog = baseline.evolution.noveltyLog.slice(-200);
      }
    }
  }

  /** Check if a sequence is novel for an agent (distance from centroid exceeds radius + margin). */
  checkNovelty(agentBuildId: string, sequence: string[]): {
    novel: boolean;
    distance: number;
    radius: number;
    maturity: string;
  } {
    const baseline = this._agentBaselines.get(agentBuildId);
    if (!baseline || baseline.count < 3) {
      return { novel: false, distance: 0, radius: 0, maturity: baseline?.maturity || "learning" };
    }

    const vector = Array.from(this._embedder.embedSequence(sequence));
    const similarity = cosineSimilarity(vector, baseline.centroid);
    const distance = 1 - similarity;
    // Novel if distance exceeds radius + 2σ margin (approximated as 1.5x radius)
    const threshold = baseline.radius * 1.5;
    const novel = distance > threshold && baseline.maturity !== "learning";

    return { novel, distance, radius: baseline.radius, maturity: baseline.maturity };
  }

  /**
   * Resolve a pending novelty entry: mark as absorbed (became normal) or confirmed (true threat).
   */
  resolveNovelty(agentBuildId: string, sequenceHash: string, outcome: "absorbed" | "confirmed"): void {
    const baseline = this._agentBaselines.get(agentBuildId);
    if (!baseline) return;
    const entry = baseline.evolution.noveltyLog.find(
      e => e.sequenceHash === sequenceHash && e.outcome === "pending",
    );
    if (entry) {
      entry.outcome = outcome;
      entry.resolvedAt = Date.now();
      this._dirty = true;
    }
  }

  // ─── URL correlation ───

  /**
   * Record a URL visit and the subsequent tool-call sequence.
   * Called at session end for each URL encountered.
   */
  recordUrlVisit(
    url: string,
    agentBuildId: string,
    sessionId: string,
    sequenceAfterUrl: string[],
    flagged: boolean,
  ): { malicious: boolean; confidence: number } | null {
    if (sequenceAfterUrl.length === 0) return null;

    const vector = Array.from(this._embedder.embedSequence(sequenceAfterUrl));

    let fp = this._urlFingerprints.get(url);
    if (!fp) {
      fp = { url, sessionFingerprints: [], malicious: false, confidence: 0 };
      this._urlFingerprints.set(url, fp);
    }

    fp.sessionFingerprints.push({
      sessionId, agentBuildId, sequenceAfterUrl, vector, timestamp: Date.now(), flagged,
    });

    // Cap fingerprints per URL at 50
    if (fp.sessionFingerprints.length > 50) {
      fp.sessionFingerprints = fp.sessionFingerprints.slice(-50);
    }

    // Check cross-session correlation
    this._evaluateUrlCorrelation(fp);
    this._dirty = true;

    if (fp.malicious) return { malicious: true, confidence: fp.confidence };
    return null;
  }

  /** Check if a URL is known malicious. */
  isUrlMalicious(url: string): { malicious: boolean; confidence: number } {
    const fp = this._urlFingerprints.get(url);
    if (!fp) return { malicious: false, confidence: 0 };
    return { malicious: fp.malicious, confidence: fp.confidence };
  }

  /**
   * Evaluate cross-session URL correlation.
   * Malicious if 3+ sessions from different agents produce similar post-fetch
   * sequences (cosine > 0.8) and at least one was flagged.
   */
  private _evaluateUrlCorrelation(fp: UrlFingerprint): void {
    const prints = fp.sessionFingerprints;
    if (prints.length < 3) return;

    // Count distinct agents
    const agents = new Set(prints.map(p => p.agentBuildId));
    if (agents.size < 2) return; // Need at least 2 different agents

    // Check if at least one was flagged
    const anyFlagged = prints.some(p => p.flagged);
    if (!anyFlagged) return;

    // Check pairwise similarity of post-fetch sequences
    let highSimilarityPairs = 0;
    let totalPairs = 0;
    for (let i = 0; i < prints.length; i++) {
      for (let j = i + 1; j < prints.length; j++) {
        if (prints[i].agentBuildId === prints[j].agentBuildId) continue;
        totalPairs++;
        const sim = cosineSimilarity(prints[i].vector, prints[j].vector);
        if (sim > 0.8) highSimilarityPairs++;
      }
    }

    if (totalPairs === 0) return;
    const correlation = highSimilarityPairs / totalPairs;

    if (correlation > 0.5 && highSimilarityPairs >= 2) {
      fp.malicious = true;
      fp.confidence = Math.min(1, correlation);
    }
  }

  // ─── LRU eviction ───

  private _evictWorkflows(): void {
    if (this._workflows.length > this._maxWorkflows) {
      // Remove oldest entries
      const excess = this._workflows.length - this._maxWorkflows;
      this._workflows.splice(0, excess);
    }
  }

  // ─── Persistence ───

  private _filePath(): string {
    return join(this._profileDir, "vector-store.json");
  }

  private _load(): void {
    const fp = this._filePath();
    if (!existsSync(fp)) return;
    try {
      const raw = readFileSync(fp, "utf-8");
      const data: VectorStoreData = JSON.parse(raw);
      if (data.version !== 1) return; // Incompatible version — start fresh

      this._workflows = data.workflows || [];
      this._clusters = data.clusters || [];
      for (const uf of (data.urlFingerprints || [])) {
        this._urlFingerprints.set(uf.url, uf);
      }
      for (const [id, bl] of Object.entries(data.agentBaselines || {})) {
        this._agentBaselines.set(id, bl);
      }
    } catch {
      // Corrupt file — start fresh
    }
  }

  flush(): void {
    if (!this._dirty) return;
    try {
      mkdirSync(this._profileDir, { recursive: true });
      const data: VectorStoreData = {
        version: 1,
        workflows: this._workflows,
        clusters: this._clusters,
        urlFingerprints: [...this._urlFingerprints.values()],
        agentBaselines: Object.fromEntries(this._agentBaselines),
        lastFlushed: Date.now(),
      };
      writeFileSync(this._filePath(), JSON.stringify(data), "utf-8");
      this._dirty = false;
    } catch {
      // Best-effort
    }
  }

  // ─── Accessors (for dashboard) ───

  getWorkflows(): readonly WorkflowEntry[] { return this._workflows; }
  getClusters(): readonly WorkflowCluster[] { return this._clusters; }
  getUrlFingerprints(): UrlFingerprint[] { return [...this._urlFingerprints.values()]; }
  getAgentBaseline(buildId: string): AgentVectorBaseline | undefined { return this._agentBaselines.get(buildId); }
  getAllAgentBaselines(): AgentVectorBaseline[] { return [...this._agentBaselines.values()]; }
  getEmbedder(): SequenceEmbedder { return this._embedder; }

  /** Load transition stats for an agent into the causal coherence tracker. */
  getTransitionStats(buildId: string): TransitionStatsMap {
    return this._agentBaselines.get(buildId)?.transitionStats || {};
  }

  /** Save transition stats from the causal coherence tracker. */
  setTransitionStats(buildId: string, stats: TransitionStatsMap): void {
    const baseline = this._agentBaselines.get(buildId);
    if (baseline) {
      baseline.transitionStats = stats;
      // Update per-transition maturity
      for (const [key, rs] of Object.entries(stats)) {
        if (!baseline.evolution.transitionMaturity[key]) {
          baseline.evolution.transitionMaturity[key] = { n: rs.n };
        } else {
          baseline.evolution.transitionMaturity[key].n = rs.n;
        }
        // Mark as stable when n >= 10 and stddev is < 20% of mean
        if (rs.n >= 10 && !baseline.evolution.transitionMaturity[key].stableAt) {
          const { m2, n: count, mean } = rs;
          const sd = count >= 2 ? Math.sqrt(m2 / count) : 0;
          if (mean > 0 && sd / mean < 0.2) {
            baseline.evolution.transitionMaturity[key].stableAt = Date.now();
          }
        }
      }
      this._dirty = true;
    }
  }
}

// ─── Security event builders ───

export function buildNovelWorkflowEvent(
  agentLabel: string,
  sequence: string[],
  distance: number,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.NOVEL_WORKFLOW,
    signatureId: "novel_workflow_sequence",
    severity: distance > 0.5 ? "high" : "medium",
    matchedText: `${agentLabel}: ${sequence.join("→")} (distance=${distance.toFixed(3)})`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: `Novel tool-call sequence never seen for this agent: ${sequence.slice(0, 5).join("→")}${sequence.length > 5 ? "..." : ""}`,
  };
}

export function buildUrlCorrelationEvent(
  url: string,
  confidence: number,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.URL_CORRELATION,
    signatureId: "cross_session_url_correlation",
    severity: confidence > 0.8 ? "high" : "medium",
    matchedText: `${url} (confidence=${confidence.toFixed(2)})`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: `Cross-session correlation: multiple agents produced similar anomalous behavior after visiting ${url}`,
  };
}
