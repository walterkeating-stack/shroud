/**
 * Semantic drift detection — TF-IDF cosine similarity tracks whether the
 * agent's tool calls are still pointed at the user's original goal.
 *
 * Core idea: prompt injection causes a topic shift. The user asked about a
 * PDF and suddenly the agent is composing an email. Drift detection measures
 * the distance between where the agent is heading and where the user pointed
 * it. Not content inspection — geometry.
 *
 * Uses the feature hashing trick to project sparse TF-IDF vectors into
 * fixed-size dense Float64Arrays. This gives a uniform interface whether
 * we later swap in real embeddings or keep TF-IDF.
 *
 * Zero external dependencies — pure math on Node.js builtins.
 */

import type { SecurityEvent, SecuritySeverity } from "../security-event.js";
import { ThreatClass } from "../security-event.js";

// ─── Vector provider interface ───

/** Pluggable vector provider — TF-IDF now, real embeddings later. */
export interface VectorProvider {
  embed(text: string): Float64Array;
  similarity(a: Float64Array, b: Float64Array): number;
  readonly dimensions: number;
}

// ─── TF-IDF provider with feature hashing ───

/**
 * Feature hashing (the "hash trick"): maps arbitrary vocabulary into a
 * fixed-size dense vector without needing a pre-built dictionary.
 *
 * How it works:
 * 1. Tokenize text into words
 * 2. Hash each word to get a bucket index (0..dimensions-1)
 * 3. Hash the word again to get a sign (+1 or -1) — reduces collision bias
 * 4. Accumulate: vector[bucket] += sign * tf_weight
 * 5. L2-normalize the result
 *
 * This produces a dense Float64Array of fixed size regardless of vocabulary.
 * Collisions are rare at 256 dimensions for the short texts we're embedding
 * (tool call descriptions, user messages). The sign trick ensures collisions
 * cancel out in expectation rather than accumulating.
 */

/** English stopwords — excluded from vectors to focus on content words. */
const STOPWORDS = new Set([
  "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "shall",
  "should", "may", "might", "must", "can", "could", "i", "you", "he",
  "she", "it", "we", "they", "me", "him", "her", "us", "them", "my",
  "your", "his", "its", "our", "their", "this", "that", "these", "those",
  "am", "in", "on", "at", "to", "for", "of", "with", "by", "from",
  "as", "into", "through", "during", "before", "after", "above", "below",
  "between", "out", "off", "over", "under", "again", "further", "then",
  "once", "here", "there", "when", "where", "why", "how", "all", "both",
  "each", "few", "more", "most", "other", "some", "such", "no", "nor",
  "not", "only", "own", "same", "so", "than", "too", "very", "just",
  "about", "up", "down", "and", "but", "or", "if", "while", "because",
]);

/** Simple FNV-1a hash — fast, good distribution for short strings. */
function fnv1a(str: string): number {
  let hash = 0x811c9dc5; // FNV offset basis
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) | 0; // FNV prime, keep 32-bit
  }
  return hash >>> 0; // unsigned
}

/** Tokenize text: lowercase, split on non-alphanumeric, remove stopwords. */
export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(t => t.length > 1 && !STOPWORDS.has(t));
}

export class TfIdfProvider implements VectorProvider {
  readonly dimensions: number;

  constructor(dimensions = 256) {
    this.dimensions = dimensions;
  }

  embed(text: string): Float64Array {
    const tokens = tokenize(text);
    const vec = new Float64Array(this.dimensions);

    if (tokens.length === 0) return vec;

    // Count term frequencies
    const tf = new Map<string, number>();
    for (const t of tokens) {
      tf.set(t, (tf.get(t) || 0) + 1);
    }

    // Feature hashing with sign trick
    for (const [term, count] of tf) {
      const bucket = fnv1a(term) % this.dimensions;
      // Sign from a second hash to reduce collision bias
      const sign = (fnv1a(term + "\x00") & 1) === 0 ? 1 : -1;
      // TF weight: 1 + log(count) to dampen frequent terms
      const weight = 1 + Math.log(count);
      vec[bucket] += sign * weight;
    }

    // L2 normalize
    let norm = 0;
    for (let i = 0; i < this.dimensions; i++) {
      norm += vec[i] * vec[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < this.dimensions; i++) {
        vec[i] /= norm;
      }
    }

    return vec;
  }

  similarity(a: Float64Array, b: Float64Array): number {
    let dot = 0;
    for (let i = 0; i < this.dimensions; i++) {
      dot += a[i] * b[i];
    }
    // Clamp to [0, 1] — negative similarity treated as 0 (completely unrelated)
    return Math.max(0, Math.min(1, dot));
  }
}

// ─── Tool call description ───

/**
 * Build a natural language description of a tool call for embedding.
 * This is what gets compared against the user's original message.
 */
export function describeToolCall(toolName: string, params: unknown): string {
  const p = (typeof params === "object" && params !== null) ? params as Record<string, unknown> : {};

  switch (toolName.toLowerCase()) {
    case "read":
    case "read_file":
      return `reading file ${p.file_path || p.path || ""}`;
    case "write":
    case "write_file":
      return `writing file ${p.file_path || p.path || ""}`;
    case "edit":
      return `editing file ${p.file_path || p.path || ""}`;
    case "exec":
    case "bash":
    case "code_execution":
      return `executing command ${String(p.command || p.code || "").slice(0, 100)}`;
    case "web_fetch":
    case "fetch":
    case "browser":
      return `fetching url ${p.url || p.uri || ""}`;
    case "message":
    case "sessions_send":
      return `sending message ${p.channel || p.recipient || ""}`;
    case "sessions_spawn":
      return `spawning agent session`;
    case "memory_search":
      return `searching memory ${p.query || ""}`;
    case "memory_get":
      return `reading memory ${p.key || p.id || ""}`;
    default:
      // For unknown tools, include tool name + first string param value
      const firstStr = Object.values(p).find(v => typeof v === "string");
      return `${toolName} ${firstStr ? String(firstStr).slice(0, 80) : ""}`;
  }
}

// ─── Drift detector ───

/** Result of a drift check on a single tool call. */
export interface DriftResult {
  /** Cosine similarity to reference intent (0-1). */
  similarity: number;
  /** Whether this tool call has drifted below threshold. */
  drifted: boolean;
  /** Whether similarity dropped sharply from previous step. */
  suddenTurn: boolean;
  /** The delta from previous step (negative = drifting away). */
  delta: number;
  /** Severity based on drift magnitude. */
  severity: SecuritySeverity;
  /** Human-readable reason. */
  reason: string;
}

/** A point on the drift trajectory — for audit/visualization. */
export interface DriftPoint {
  step: number;
  toolName: string;
  similarity: number;
  delta: number;
  timestamp: number;
}

/**
 * Tracks semantic drift across a conversation turn.
 *
 * Set the reference from the user's message, then check each tool call.
 * The trajectory is stored for audit logging and dashboard visualization.
 */
export class DriftDetector {
  private _provider: VectorProvider;
  private _referenceVec: Float64Array | null = null;
  private _referenceText = "";
  private _trajectory: DriftPoint[] = [];
  private _prevSimilarity = 1.0;
  private _driftThreshold: number;
  private _suddenTurnDelta: number;

  constructor(opts: {
    provider?: VectorProvider;
    driftThreshold?: number;
    suddenTurnDelta?: number;
  } = {}) {
    this._provider = opts.provider ?? new TfIdfProvider(256);
    this._driftThreshold = opts.driftThreshold ?? 0.15;
    this._suddenTurnDelta = opts.suddenTurnDelta ?? 0.3;
  }

  /** Set the reference vector from the user's original message. */
  setReference(userMessage: string): void {
    this._referenceText = userMessage;
    this._referenceVec = this._provider.embed(userMessage);
    // Don't clear trajectory — accumulate across turns for dashboard visualization.
    // Reset similarity baseline so the first tool call in a new turn isn't a "sudden turn".
    this._prevSimilarity = 1.0;
  }

  /** Check if a tool call has drifted from the user's intent. */
  checkDrift(toolName: string, params: unknown): DriftResult {
    if (!this._referenceVec) {
      return { similarity: 1, drifted: false, suddenTurn: false, delta: 0, severity: "low", reason: "" };
    }

    const description = describeToolCall(toolName, params);
    const toolVec = this._provider.embed(description);
    const similarity = this._provider.similarity(this._referenceVec, toolVec);
    const delta = similarity - this._prevSimilarity;
    const suddenTurn = delta < -this._suddenTurnDelta;
    const drifted = similarity < this._driftThreshold;

    // Record trajectory point (cap at 200 to bound memory)
    this._trajectory.push({
      step: this._trajectory.length + 1,
      toolName,
      similarity,
      delta,
      timestamp: Date.now(),
    });
    if (this._trajectory.length > 200) this._trajectory.shift();

    this._prevSimilarity = similarity;

    // Determine severity
    // High requires a sudden turn (sharp drop from previous step) — not just
    // low absolute similarity, which TF-IDF naturally produces for short texts
    // with no shared vocabulary. Low absolute similarity alone is medium.
    let severity: SecuritySeverity = "low";
    let reason = "";

    if (suddenTurn && similarity < 0.05) {
      severity = "high";
      reason = `Sharp trajectory turn: similarity dropped ${Math.abs(delta).toFixed(2)} to ${similarity.toFixed(2)} on "${toolName}" — intent "${this._referenceText.slice(0, 60)}"`;
    } else if (suddenTurn || (drifted && similarity < 0.05)) {
      severity = "medium";
      reason = suddenTurn
        ? `Trajectory turn: similarity dropped ${Math.abs(delta).toFixed(2)} on "${toolName}"`
        : `Drift detected: "${toolName}" has ${similarity.toFixed(2)} similarity to user intent`;
    } else if (drifted) {
      severity = "medium";
      reason = `Drift detected: "${toolName}" has ${similarity.toFixed(2)} similarity to user intent`;
    }

    return { similarity, drifted, suddenTurn, delta, severity, reason };
  }

  /** Get the full trajectory for audit/visualization. */
  getTrajectory(): readonly DriftPoint[] {
    return this._trajectory;
  }

  /** Get the reference text. */
  getReferenceText(): string {
    return this._referenceText;
  }

  /** Get the vector provider (for dashboard dimension info). */
  getProvider(): VectorProvider {
    return this._provider;
  }

  /** Reset for a new turn. */
  reset(): void {
    this._referenceVec = null;
    this._referenceText = "";
    this._trajectory = [];
    this._prevSimilarity = 1.0;
  }
}

// ─── Security event builder ───

/** Build a SecurityEvent from a drift result. */
export function buildDriftEvent(
  toolName: string,
  result: DriftResult,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.SEMANTIC_DRIFT,
    signatureId: result.suddenTurn ? "drift_sudden_turn" : "drift_threshold",
    severity: result.severity,
    matchedText: `${toolName}: similarity=${result.similarity.toFixed(3)} delta=${result.delta.toFixed(3)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: result.reason,
  };
}
