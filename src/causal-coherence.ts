/**
 * Causal coherence tracking — monitors the semantic relationship between
 * tool results and subsequent tool calls.
 *
 * Core idea: for legitimate workflows, there's a predictable relationship
 * between what the model received (tool result) and what it decides to do
 * next (tool call). Reading a Python file leads to an edit or test run.
 * Reading a web page leads to fetching one of the returned URLs.
 *
 * When an injection fires, this causal link breaks. The model reads a web
 * page but then calls message with a payload closer to the user's private
 * context than to the page it just read. The input-output pair doesn't match.
 *
 * We embed both sides — result text and next-call description — as pairs,
 * track the distance between them with Welford's running stats, and flag
 * when the z-score exceeds a threshold.
 *
 * Zero external dependencies.
 */

import type { VectorProvider } from "./detectors/drift-detector.js";
import { TfIdfProvider, describeToolCall } from "./detectors/drift-detector.js";
import type { SecurityEvent, SecuritySeverity } from "./security-event.js";
import { ThreatClass } from "./security-event.js";
import type { RunningStats } from "./profiler-types.js";
import { emptyStats, updateStats, stddev, zScore } from "./profiler-analysis.js";

// ─── Types ───

/** A result→action transition pair. */
export interface TransitionPair {
  resultToolName: string;
  actionToolName: string;
  distance: number;
  timestamp: number;
}

/** Running stats for transition distances, keyed by "toolA→toolB". */
export interface TransitionStatsMap {
  [transitionKey: string]: RunningStats;
}

/** Result of a coherence check on a single transition. */
export interface CoherenceResult {
  /** Whether this transition is coherent with baseline. */
  coherent: boolean;
  /** Cosine distance between result and action embeddings (1 - similarity). */
  distance: number;
  /** Baseline mean distance for this transition type. */
  expectedDistance: number;
  /** Z-score: how many σ from baseline. */
  zScore: number;
  /** Severity based on z-score magnitude. */
  severity: SecuritySeverity;
  /** Human-readable reason (empty if coherent). */
  reason: string;
  /** Transition key ("toolA→toolB"). */
  transitionKey: string;
}

// ─── Coherence tracker ───

/**
 * Tracks causal coherence between adjacent steps in the tool-call chain.
 *
 * Usage:
 * 1. Call feedResult() when a tool result is received (tool_result_persist hook)
 * 2. Call checkCoherence() when the next tool call fires (before_tool_call hook)
 *
 * The tracker maintains per-transition running stats (Welford's algorithm)
 * for the cosine distance between result embeddings and action embeddings.
 */
export class CausalCoherenceTracker {
  private _provider: VectorProvider;
  private _zScoreThreshold: number;
  private _resultLimit: number;

  // Pending result from last tool — consumed by next checkCoherence()
  private _pendingResultVec: Float64Array | null = null;
  private _pendingResultToolName = "";

  // Per-agent transition stats (loaded from / persisted to vector store)
  private _stats: TransitionStatsMap = {};

  // Recent pairs for dashboard (ring buffer, max 50)
  private _recentPairs: TransitionPair[] = [];
  private _maxRecentPairs = 50;

  constructor(opts: {
    provider?: VectorProvider;
    zScoreThreshold?: number;
    resultLimit?: number;
    stats?: TransitionStatsMap;
  } = {}) {
    this._provider = opts.provider ?? new TfIdfProvider(256);
    this._zScoreThreshold = opts.zScoreThreshold ?? 3.0;
    this._resultLimit = opts.resultLimit ?? 500;
    if (opts.stats) this._stats = opts.stats;
  }

  /**
   * Feed a tool result into the tracker.
   * Called from tool_result_persist hook.
   *
   * @param toolName - The tool that produced this result
   * @param resultText - The result text (truncated to resultLimit)
   */
  feedResult(toolName: string, resultText: string): void {
    const truncated = resultText.slice(0, this._resultLimit);
    if (!truncated.trim()) {
      this._pendingResultVec = null;
      this._pendingResultToolName = "";
      return;
    }
    this._pendingResultVec = this._provider.embed(truncated);
    this._pendingResultToolName = toolName;
  }

  /**
   * Check coherence between the pending result and the next tool call.
   * Called from before_tool_call hook.
   *
   * Returns null if no pending result (first tool call in turn, or result was empty).
   */
  checkCoherence(toolName: string, params: unknown): CoherenceResult | null {
    if (!this._pendingResultVec) return null;

    const actionDesc = describeToolCall(toolName, params);
    const actionVec = this._provider.embed(actionDesc);
    const similarity = this._provider.similarity(this._pendingResultVec, actionVec);
    const distance = 1 - similarity;

    const key = `${this._pendingResultToolName}\u2192${toolName}`;

    // Look up baseline for this transition
    const baseline = this._stats[key];
    let z = 0;
    let expectedDistance = distance; // No baseline → distance is "expected"

    if (baseline && baseline.n >= 3) {
      const sd = stddev(baseline);
      z = zScore(distance, baseline.mean, sd);
      expectedDistance = baseline.mean;
    }

    // Update running stats with this observation
    if (!this._stats[key]) this._stats[key] = emptyStats();
    this._stats[key] = updateStats(this._stats[key], distance);

    // Record pair
    const pair: TransitionPair = {
      resultToolName: this._pendingResultToolName,
      actionToolName: toolName,
      distance,
      timestamp: Date.now(),
    };
    this._recentPairs.push(pair);
    if (this._recentPairs.length > this._maxRecentPairs) this._recentPairs.shift();

    // Clear pending result (consumed)
    this._pendingResultVec = null;
    this._pendingResultToolName = "";

    // Determine coherence
    const incoherent = baseline && baseline.n >= 3 && Math.abs(z) > this._zScoreThreshold;

    let severity: SecuritySeverity = "low";
    let reason = "";

    if (incoherent) {
      if (Math.abs(z) > this._zScoreThreshold * 1.5) {
        severity = "high";
        reason = `Causal break: ${key} distance=${distance.toFixed(3)} (expected=${expectedDistance.toFixed(3)}, z=${z.toFixed(2)}) — input-output relationship severed`;
      } else {
        severity = "medium";
        reason = `Causal incoherence: ${key} distance=${distance.toFixed(3)} (expected=${expectedDistance.toFixed(3)}, z=${z.toFixed(2)})`;
      }
    }

    return {
      coherent: !incoherent,
      distance,
      expectedDistance,
      zScore: z,
      severity,
      reason,
      transitionKey: key,
    };
  }

  /** Reset pending state for a new turn. Stats are preserved (they're cross-turn). */
  resetTurn(): void {
    this._pendingResultVec = null;
    this._pendingResultToolName = "";
  }

  /** Get the transition stats (for persistence). */
  getStats(): TransitionStatsMap {
    return this._stats;
  }

  /** Load transition stats (from persistence). */
  loadStats(stats: TransitionStatsMap): void {
    this._stats = stats;
  }

  /** Get recent pairs for dashboard. */
  getRecentPairs(): readonly TransitionPair[] {
    return this._recentPairs;
  }

  /** Get the vector provider (for PCA projection). */
  getProvider(): VectorProvider {
    return this._provider;
  }
}

// ─── Security event builder ───

/** Build a SecurityEvent from a coherence result. */
export function buildCoherenceEvent(
  result: CoherenceResult,
  action: "flagged" | "blocked" = "flagged",
): SecurityEvent {
  return {
    timestamp: Date.now(),
    eventType: "anomaly_detected",
    direction: "request",
    threatClass: ThreatClass.CAUSAL_INCOHERENCE,
    signatureId: result.zScore > result.zScore * 1.5
      ? "coherence_severe_break"
      : "coherence_incoherent",
    severity: result.severity,
    matchedText: `${result.transitionKey}: distance=${result.distance.toFixed(3)} z=${result.zScore.toFixed(2)}`,
    matchStart: 0,
    matchEnd: 0,
    textLength: 0,
    action,
    description: result.reason,
  };
}
