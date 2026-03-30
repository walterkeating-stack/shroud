/**
 * Types for the behavioural profiling system (Track 3).
 *
 * Per-turn feature extraction, per-session aggregation,
 * cross-session baseline accumulation, and anomaly detection.
 */

/** Per-turn feature vector — all computable sync, zero-dep. */
export interface FeatureVector {
  /** Entity category → count for this turn. */
  entityCategoryCounts: Record<string, number>;
  /** Entities per 1,000 tokens. */
  entityDensityPer1k: number;
  /** Shannon entropy of entity category distribution. */
  entityCategoryEntropy: number;

  /** Number of tool calls this turn. */
  toolCallCount: number;
  /** Ordered list of tool names called this turn. */
  toolNames: string[];

  /** Count of imperative/directive verbs in the prompt. */
  directiveVerbCount: number;
  /** Count of questions (sentences ending in ?). */
  questionCount: number;
  /** Ratio of directives to questions (Infinity if questionCount=0). */
  commandToQuestionRatio: number;

  /** Response text length in characters. */
  responseLength: number;
  /** Fraction of request entities that appear in the response. */
  entityEchoRate: number;

  /** Jaccard similarity of word bigrams between this and previous turn (0-1). */
  lexicalOverlapWithPrevious: number;
  /** Fraction of words not seen in any previous turn this session. */
  newVocabularyRate: number;

  /** Turn index (0-based). */
  turnIndex: number;
  /** Timestamp (ms since epoch). */
  timestamp: number;
  /** Estimated token count (chars / 4). */
  tokenEstimate: number;

  /** Detected script/language of the input (e.g. "latin", "cjk", "cyrillic", "arabic"). */
  detectedScript: string;
  /** Fraction of non-Latin characters in the input (0-1). */
  nonLatinRatio: number;
}

/** Aggregate statistics for a session. */
export interface SessionAggregates {
  /** Top 3 entity categories by frequency. */
  dominantCategories: string[];
  /** SHA256 of sorted unique tool names. */
  toolSequenceFingerprint: string;
  /** Mean entity density across turns. */
  averageEntityDensity: number;
  /** Mean directive verb count across turns. */
  averageDirectiveVerbCount: number;
  /** Mean response length across turns. */
  averageResponseLength: number;
  /** Mean lexical overlap across turns. */
  averageLexicalOverlap: number;
  /** Total turn count. */
  turnCount: number;
}

/** A session's full profile. */
export interface SessionProfile {
  sessionId: string;
  agentBuildId: string;
  startedAt: number;
  turns: FeatureVector[];
  aggregates: SessionAggregates;
}

/** Running statistics for a single feature (Welford's algorithm). */
export interface RunningStats {
  mean: number;
  m2: number;   // sum of (x - mean)^2 increments
  n: number;
  min: number;
  max: number;
}

/** Baseline for a feature set derived from multiple sessions. */
export interface BaselineFeatureStats {
  [featureName: string]: RunningStats;
}

/** Baseline maturity level. */
export type BaselineMaturity = "learning" | "reliable" | "mature";

/** Agent baseline — cross-session profile keyed by build ID. */
export interface AgentBaseline {
  agentBuildId: string;
  sessionCount: number;
  maturity: BaselineMaturity;
  features: BaselineFeatureStats;
  toolProfile: string[];
  categoryProfile: string[];
  lastUpdated: number;
}

/** Named anomaly types modelled on IDS alert categories. */
export enum AnomalyType {
  ENTITY_CATEGORY_SHIFT = "entity_category_shift",
  ENTITY_DENSITY_SPIKE = "entity_density_spike",
  TOOL_OUTSIDE_PROFILE = "tool_outside_profile",
  TOPIC_DISCONTINUITY = "topic_discontinuity",
  CREDENTIAL_EMERGENCE = "credential_emergence",
  EXFILTRATION_PATTERN = "exfiltration_pattern",
}

/** An anomaly alert emitted when profiler detects deviation. */
export interface AnomalyAlert {
  type: AnomalyType;
  severity: "info" | "warning" | "critical";
  feature: string;
  observedValue: number;
  baselineMean: number;
  baselineStddev: number;
  zScore: number;
  turnIndex: number;
  timestamp: number;
  description: string;
}
