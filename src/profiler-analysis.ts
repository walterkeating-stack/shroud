/**
 * Statistical analysis utilities for behavioural profiling.
 *
 * Welford's online algorithm for incremental mean/stddev,
 * Z-score computation, and multi-feature anomaly scoring.
 * All synchronous, zero dependencies.
 */

import {
  AnomalyAlert,
  AnomalyType,
  BaselineFeatureStats,
  FeatureVector,
  RunningStats,
} from "./profiler-types.js";

// ===================================================================
// Welford's Online Algorithm
// ===================================================================

/** Create a fresh running stats accumulator. */
export function emptyStats(): RunningStats {
  return { mean: 0, m2: 0, n: 0, min: Infinity, max: -Infinity };
}

/**
 * Update running stats with a new observation.
 * Uses Welford's algorithm for numerically stable incremental mean/variance.
 */
export function updateStats(stats: RunningStats, x: number): RunningStats {
  const n = stats.n + 1;
  const delta = x - stats.mean;
  const mean = stats.mean + delta / n;
  const delta2 = x - mean;
  const m2 = stats.m2 + delta * delta2;

  return {
    mean,
    m2,
    n,
    min: Math.min(stats.min, x),
    max: Math.max(stats.max, x),
  };
}

/** Compute standard deviation from running stats. */
export function stddev(stats: RunningStats): number {
  if (stats.n < 2) return 0;
  return Math.sqrt(stats.m2 / stats.n);
}

// ===================================================================
// Z-Score and Anomaly Detection
// ===================================================================

/** Compute Z-score. Returns 0 if stddev is 0 and value equals mean. */
export function zScore(observed: number, mean: number, sd: number): number {
  if (sd === 0) return observed === mean ? 0 : Infinity;
  return (observed - mean) / sd;
}

/** Features extracted from a FeatureVector that we track in the baseline. */
const NUMERIC_FEATURES: Array<{
  name: string;
  extract: (fv: FeatureVector) => number;
  anomalyType: AnomalyType;
}> = [
  {
    name: "entityDensityPer1k",
    extract: (fv) => fv.entityDensityPer1k,
    anomalyType: AnomalyType.ENTITY_DENSITY_SPIKE,
  },
  {
    name: "entityCategoryEntropy",
    extract: (fv) => fv.entityCategoryEntropy,
    anomalyType: AnomalyType.ENTITY_CATEGORY_SHIFT,
  },
  {
    name: "toolCallCount",
    extract: (fv) => fv.toolCallCount,
    anomalyType: AnomalyType.TOOL_OUTSIDE_PROFILE,
  },
  {
    name: "directiveVerbCount",
    extract: (fv) => fv.directiveVerbCount,
    anomalyType: AnomalyType.ENTITY_CATEGORY_SHIFT,
  },
  {
    name: "commandToQuestionRatio",
    extract: (fv) => isFinite(fv.commandToQuestionRatio) ? fv.commandToQuestionRatio : 10,
    anomalyType: AnomalyType.ENTITY_CATEGORY_SHIFT,
  },
  {
    name: "responseLength",
    extract: (fv) => fv.responseLength,
    anomalyType: AnomalyType.EXFILTRATION_PATTERN,
  },
  {
    name: "entityEchoRate",
    extract: (fv) => fv.entityEchoRate,
    anomalyType: AnomalyType.EXFILTRATION_PATTERN,
  },
  {
    name: "lexicalOverlapWithPrevious",
    extract: (fv) => fv.lexicalOverlapWithPrevious,
    anomalyType: AnomalyType.TOPIC_DISCONTINUITY,
  },
  {
    name: "newVocabularyRate",
    extract: (fv) => fv.newVocabularyRate,
    anomalyType: AnomalyType.TOPIC_DISCONTINUITY,
  },
  {
    name: "tokenEstimate",
    extract: (fv) => fv.tokenEstimate,
    anomalyType: AnomalyType.ENTITY_DENSITY_SPIKE,
  },
];

/**
 * Detect anomalies by comparing a feature vector against the baseline.
 *
 * @param features - Current turn's feature vector
 * @param baseline - Accumulated baseline feature statistics
 * @param sigma - Z-score threshold (default 3.0)
 * @param knownTools - Set of tool names seen in baseline sessions
 * @param knownCategories - Set of entity categories seen in baseline sessions
 */
export function detectAnomalies(
  features: FeatureVector,
  baseline: BaselineFeatureStats,
  sigma: number,
  knownTools: Set<string>,
  knownCategories: Set<string>,
): AnomalyAlert[] {
  const alerts: AnomalyAlert[] = [];
  const ts = features.timestamp;
  const turn = features.turnIndex;

  // Z-score based anomalies for numeric features
  for (const feat of NUMERIC_FEATURES) {
    const stats = baseline[feat.name];
    if (!stats || stats.n < 2) continue; // Not enough data

    const observed = feat.extract(features);
    const sd = stddev(stats);
    const z = zScore(observed, stats.mean, sd);

    if (Math.abs(z) > sigma) {
      const severity = Math.abs(z) > sigma * 1.5 ? "critical" : "warning";
      alerts.push({
        type: feat.anomalyType,
        severity,
        feature: feat.name,
        observedValue: observed,
        baselineMean: stats.mean,
        baselineStddev: sd,
        zScore: z,
        turnIndex: turn,
        timestamp: ts,
        description: `${feat.name}: z=${z.toFixed(2)} (observed=${observed.toFixed(2)}, baseline=${stats.mean.toFixed(2)}±${sd.toFixed(2)})`,
      });
    }
  }

  // Tool outside profile — tool name never seen in baseline
  if (knownTools.size > 0) {
    for (const tool of features.toolNames) {
      if (!knownTools.has(tool)) {
        alerts.push({
          type: AnomalyType.TOOL_OUTSIDE_PROFILE,
          severity: "warning",
          feature: "toolName",
          observedValue: 1,
          baselineMean: 0,
          baselineStddev: 0,
          zScore: Infinity,
          turnIndex: turn,
          timestamp: ts,
          description: `Tool "${tool}" not in baseline tool set`,
        });
      }
    }
  }

  // Credential emergence — credential-like categories appearing for first time
  const credentialCategories = new Set(["api_key", "jwt", "network_credential", "certificate"]);
  for (const [cat, count] of Object.entries(features.entityCategoryCounts)) {
    if (credentialCategories.has(cat) && count > 0 && !knownCategories.has(cat)) {
      alerts.push({
        type: AnomalyType.CREDENTIAL_EMERGENCE,
        severity: "critical",
        feature: `category:${cat}`,
        observedValue: count,
        baselineMean: 0,
        baselineStddev: 0,
        zScore: Infinity,
        turnIndex: turn,
        timestamp: ts,
        description: `Credential category "${cat}" appeared (count=${count}) with no baseline history`,
      });
    }
  }

  return alerts;
}

/**
 * Update the baseline with feature values from a completed turn.
 */
export function updateBaseline(
  baseline: BaselineFeatureStats,
  features: FeatureVector,
): BaselineFeatureStats {
  const updated = { ...baseline };

  for (const feat of NUMERIC_FEATURES) {
    const value = feat.extract(features);
    if (!updated[feat.name]) {
      updated[feat.name] = emptyStats();
    }
    updated[feat.name] = updateStats(updated[feat.name], value);
  }

  return updated;
}

/** Get the list of tracked numeric feature names. */
export function getTrackedFeatureNames(): string[] {
  return NUMERIC_FEATURES.map((f) => f.name);
}
