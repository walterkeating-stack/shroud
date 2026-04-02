/**
 * Adaptive threshold engine — auto-tunes detection thresholds
 * from behavioural profiler baselines.
 *
 * Mature agents with established behavioural patterns get widened
 * thresholds to reduce false positives. Learning-phase agents use
 * global defaults. All adjustments have hard caps to prevent
 * security bypass.
 *
 * Zero runtime dependencies.
 */

import type { AgentBaseline, RunningStats } from "./profiler-types.js";
import type { ShroudConfig } from "./types.js";

/** Per-agent adaptive thresholds computed from baseline data. */
export interface AgentThresholds {
  /** Widened if agent has high topic variance (default: config.driftThreshold). */
  driftThreshold: number;
  /** Widened if agent has diverse tool patterns (default: config.coherenceZScore). */
  coherenceZScore: number;
  /** Raised if agent uses diverse tools or has high entity density (default: config.transformerThreshold). */
  transformerThreshold: number;
  /** Signatures that are normal behaviour for this agent — skip event emission. */
  suppressedSignatures: string[];
}

// Hard caps — thresholds can never be relaxed beyond these
// Drift fires when similarity < threshold, so LOWER = less sensitive.
// Floor prevents threshold from going so low it never triggers.
const MIN_DRIFT_THRESHOLD = 0.05;
const MIN_COHERENCE_ZSCORE = 1.5;
const MAX_TRANSFORMER_THRESHOLD = 0.95;

// Multipliers for mature/reliable agents
const DRIFT_WIDEN_FACTOR = 1.5;
const COHERENCE_WIDEN_FACTOR = 1.3;
const TRANSFORMER_RAISE_FACTOR = 1.2;

// Thresholds for determining "high variance" or "diverse tools"
const HIGH_LEXICAL_OVERLAP_STDDEV = 0.25;
const DIVERSE_TOOL_COUNT = 8;
const HIGH_ENTITY_DENSITY_MEAN = 5.0;

/**
 * Compute adaptive thresholds for an agent based on its profiler baseline.
 *
 * Returns global defaults if the baseline is immature or absent.
 */
export function computeAdaptiveThresholds(
  baseline: AgentBaseline | null,
  config: ShroudConfig,
): AgentThresholds {
  const defaults: AgentThresholds = {
    driftThreshold: config.driftThreshold,
    coherenceZScore: config.coherenceZScore,
    transformerThreshold: config.transformerThreshold,
    suppressedSignatures: [],
  };

  if (!baseline) return defaults;
  if (baseline.maturity === "learning") return defaults;

  // Only adjust for "reliable" or "mature" baselines
  let drift = config.driftThreshold;
  let coherence = config.coherenceZScore;
  let transformer = config.transformerThreshold;
  const suppressed: string[] = [];

  // 1. High topic variance → lower drift threshold (less sensitive)
  //    lexicalOverlapWithPrevious stddev indicates how much the agent's
  //    conversation topics vary from turn to turn.
  //    Note: drift fires when similarity < threshold, so LOWER threshold = less sensitive.
  const lexOverlap = baseline.features["lexicalOverlapWithPrevious"];
  if (lexOverlap && getStddev(lexOverlap) > HIGH_LEXICAL_OVERLAP_STDDEV) {
    drift /= DRIFT_WIDEN_FACTOR;
  }

  // 2. Diverse tool patterns → widen coherence z-score
  //    Agents with many different tools in their profile naturally produce
  //    more varied result→action pairs.
  if (baseline.toolProfile.length >= DIVERSE_TOOL_COUNT) {
    coherence *= COHERENCE_WIDEN_FACTOR;
  }

  // 3. High entity density as normal → raise transformer threshold
  //    Agents that routinely handle entity-dense content shouldn't trigger
  //    on the same density patterns.
  const entityDensity = baseline.features["entityDensityPer1k"];
  if (entityDensity && entityDensity.mean > HIGH_ENTITY_DENSITY_MEAN) {
    transformer *= TRANSFORMER_RAISE_FACTOR;
  }

  // 4. Tools flagged as "unexpected" that appear in the agent's baseline
  //    tool profile → suppress tool_outside_profile signatures
  if (baseline.toolProfile.length > 0) {
    suppressed.push("tool_outside_profile");
  }

  // 5. For mature baselines with high session counts, suppress signatures
  //    that correspond to the agent's known behavioural patterns
  if (baseline.maturity === "mature") {
    // Agents with consistently high new vocabulary rate are research/exploration agents
    const newVocab = baseline.features["newVocabularyRate"];
    if (newVocab && newVocab.mean > 0.3) {
      suppressed.push("topic_discontinuity");
    }

    // Agents with consistently high entity density are data-processing agents
    if (entityDensity && entityDensity.mean > HIGH_ENTITY_DENSITY_MEAN) {
      suppressed.push("entity_density_spike");
    }
  }

  // Apply hard caps
  drift = Math.max(drift, MIN_DRIFT_THRESHOLD);
  coherence = Math.max(coherence, MIN_COHERENCE_ZSCORE);
  transformer = Math.min(transformer, MAX_TRANSFORMER_THRESHOLD);

  return {
    driftThreshold: drift,
    coherenceZScore: coherence,
    transformerThreshold: transformer,
    suppressedSignatures: suppressed,
  };
}

/** Compute standard deviation from Welford running stats. */
function getStddev(stats: RunningStats): number {
  if (stats.n < 2) return 0;
  return Math.sqrt(stats.m2 / (stats.n - 1));
}

/**
 * Check if a signature should be suppressed for a given agent
 * based on their adaptive thresholds.
 */
export function isSignatureSuppressed(
  signatureId: string,
  thresholds: AgentThresholds,
): boolean {
  return thresholds.suppressedSignatures.includes(signatureId);
}
