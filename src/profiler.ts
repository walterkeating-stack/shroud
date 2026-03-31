/**
 * Behavioural profiler for LLM agent sessions (Track 3).
 *
 * Extracts per-turn feature vectors from request/response text,
 * maintains session aggregates, and detects anomalies against
 * cross-session baselines. All feature extraction is synchronous
 * and zero-dependency.
 */

import { createHash } from "node:crypto";

import {
  AnomalyAlert,
  FeatureVector,
  SessionAggregates,
  SessionProfile,
} from "./profiler-types.js";
import { detectAnomalies, updateBaseline } from "./profiler-analysis.js";
import { BaselineStore } from "./profiler-store.js";

/** Configuration for the profiler. */
export interface ProfilerConfig {
  mode: "learning" | "active" | "strict";
  sigma: number;
  minBaseline: number;
  profileDir: string;
}

/** ~30 common imperative/directive verbs. */
const DIRECTIVE_VERBS = /\b(?:do|create|run|execute|build|make|write|read|delete|remove|update|modify|change|set|get|fetch|send|post|deploy|install|configure|enable|disable|start|stop|kill|restart|migrate|revert|rollback)\b/gi;

/** Tool call info passed from hooks layer. */
export interface ToolCallInfo {
  name: string;
  arguments?: Record<string, unknown>;
}

/**
 * Behavioural profiler. One instance per session.
 */
export class BehaviouralProfiler {
  private _config: ProfilerConfig;
  private _store: BaselineStore;
  private _sessionId: string;
  private _agentBuildId = "";
  private _turns: FeatureVector[] = [];
  private _alerts: AnomalyAlert[] = [];
  private _previousTurnBigrams: Set<string> = new Set();
  private _allSessionWords: Set<string> = new Set();
  private _startedAt: number;

  // Partial features accumulated during a turn (request side fills, response side completes)
  private _pendingRequest: Partial<FeatureVector> | null = null;

  constructor(config: ProfilerConfig, store: BaselineStore) {
    this._config = config;
    this._store = store;
    this._sessionId = createHash("sha256")
      .update(`profile:${Date.now()}:${Math.random()}`)
      .digest("hex")
      .slice(0, 12);
    this._startedAt = Date.now();
  }

  /** Set the agent build ID (derived from normalized label). */
  setAgentBuildId(buildId: string): void {
    this._agentBuildId = buildId;
  }

  /** Tool inventory for the current agent (from body.tools). */
  private _toolInventory: string[] = [];

  /** Set the full tool inventory so it can be persisted to the baseline. */
  setToolInventory(tools: string[]): void {
    this._toolInventory = tools;
  }

  /**
   * Extract features from the outbound request text.
   * Called after obfuscation, before sending to LLM.
   */
  extractRequestFeatures(
    text: string,
    entityCategoryCounts: Record<string, number>,
    toolCalls?: ToolCallInfo[],
    imagePayloads?: { count: number; totalBytes: number },
  ): void {
    const tokenEstimate = Math.ceil(text.length / 4);
    const totalEntities = Object.values(entityCategoryCounts).reduce((a, b) => a + b, 0);

    // Entity density
    const entityDensityPer1k = tokenEstimate > 0
      ? (totalEntities / tokenEstimate) * 1000
      : 0;

    // Shannon entropy of entity category distribution
    const entityCategoryEntropy = shannonEntropy(entityCategoryCounts);

    // Directive verbs
    const directiveVerbCount = (text.match(DIRECTIVE_VERBS) || []).length;

    // Questions
    const questionCount = (text.match(/\?\s/g) || []).length + (text.endsWith("?") ? 1 : 0);

    // Command-to-question ratio
    const commandToQuestionRatio = questionCount > 0
      ? directiveVerbCount / questionCount
      : directiveVerbCount > 0 ? Infinity : 0;

    // Tool calls
    const toolCallCount = toolCalls?.length ?? 0;
    const toolNames = toolCalls?.map((tc) => tc.name) ?? [];

    // Lexical analysis
    const words = extractWords(text);
    const bigrams = computeBigrams(words);

    const lexicalOverlapWithPrevious = this._previousTurnBigrams.size > 0
      ? jaccardSimilarity(bigrams, this._previousTurnBigrams)
      : 1.0; // First turn: assume no discontinuity

    // New vocabulary rate
    const newWords = words.filter((w) => !this._allSessionWords.has(w));
    const newVocabularyRate = words.length > 0 ? newWords.length / words.length : 0;

    // Update cumulative word tracking
    for (const w of words) this._allSessionWords.add(w);
    this._previousTurnBigrams = bigrams;

    // Script/language detection
    const { script, nonLatinRatio } = detectScript(text);

    this._pendingRequest = {
      entityCategoryCounts,
      entityDensityPer1k,
      entityCategoryEntropy,
      toolCallCount,
      toolNames,
      directiveVerbCount,
      questionCount,
      commandToQuestionRatio,
      lexicalOverlapWithPrevious,
      newVocabularyRate,
      turnIndex: this._turns.length,
      timestamp: Date.now(),
      tokenEstimate,
      detectedScript: script,
      nonLatinRatio,
      imagePayloadCount: imagePayloads?.count ?? 0,
      imagePayloadBytes: imagePayloads?.totalBytes ?? 0,
      // Cache metrics filled in from response (extractResponseFeatures)
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      cacheHitRatio: 0,
    };
  }

  /**
   * Complete the feature vector with response-side features.
   * Called after deobfuscation of the LLM response.
   */
  extractResponseFeatures(
    responseText: string,
    requestEntities: string[],
    cacheUsage?: { inputTokens: number; outputTokens: number; cacheReadTokens: number; cacheWriteTokens: number },
  ): FeatureVector | null {
    if (!this._pendingRequest) return null;

    const responseLength = responseText.length;

    // Entity echo rate: how many request entities appear in the response
    let echoCount = 0;
    for (const entity of requestEntities) {
      if (responseText.includes(entity)) echoCount++;
    }
    const entityEchoRate = requestEntities.length > 0
      ? echoCount / requestEntities.length
      : 0;

    const features: FeatureVector = {
      entityCategoryCounts: this._pendingRequest.entityCategoryCounts ?? {},
      entityDensityPer1k: this._pendingRequest.entityDensityPer1k ?? 0,
      entityCategoryEntropy: this._pendingRequest.entityCategoryEntropy ?? 0,
      toolCallCount: this._pendingRequest.toolCallCount ?? 0,
      toolNames: this._pendingRequest.toolNames ?? [],
      directiveVerbCount: this._pendingRequest.directiveVerbCount ?? 0,
      questionCount: this._pendingRequest.questionCount ?? 0,
      commandToQuestionRatio: this._pendingRequest.commandToQuestionRatio ?? 0,
      responseLength,
      entityEchoRate,
      lexicalOverlapWithPrevious: this._pendingRequest.lexicalOverlapWithPrevious ?? 1,
      newVocabularyRate: this._pendingRequest.newVocabularyRate ?? 0,
      turnIndex: this._pendingRequest.turnIndex ?? this._turns.length,
      timestamp: this._pendingRequest.timestamp ?? Date.now(),
      tokenEstimate: this._pendingRequest.tokenEstimate ?? 0,
      detectedScript: this._pendingRequest.detectedScript ?? "latin",
      nonLatinRatio: this._pendingRequest.nonLatinRatio ?? 0,
      imagePayloadCount: this._pendingRequest.imagePayloadCount ?? 0,
      imagePayloadBytes: this._pendingRequest.imagePayloadBytes ?? 0,
      inputTokens: cacheUsage?.inputTokens ?? 0,
      outputTokens: cacheUsage?.outputTokens ?? 0,
      cacheReadTokens: cacheUsage?.cacheReadTokens ?? 0,
      cacheWriteTokens: cacheUsage?.cacheWriteTokens ?? 0,
      cacheHitRatio: cacheUsage && cacheUsage.inputTokens > 0
        ? cacheUsage.cacheReadTokens / cacheUsage.inputTokens
        : 0,
    };

    this._turns.push(features);
    this._pendingRequest = null;

    return features;
  }

  /**
   * Analyze a completed turn against the baseline.
   * Returns anomaly alerts (empty if in learning mode or insufficient baseline).
   */
  analyzeTurn(features: FeatureVector): AnomalyAlert[] {
    if (this._config.mode === "learning") return [];
    if (!this._agentBuildId) return [];

    const baseline = this._store.load(this._agentBuildId);
    if (!baseline) return [];
    if (baseline.sessionCount < this._config.minBaseline) return [];

    const knownTools = new Set(baseline.toolProfile);
    const knownCategories = new Set(baseline.categoryProfile);

    const alerts = detectAnomalies(
      features,
      baseline.features,
      this._config.sigma,
      knownTools,
      knownCategories,
    );

    this._alerts.push(...alerts);
    return alerts;
  }

  /**
   * Finalize the session: compute aggregates, update baseline store.
   */
  finalizeSession(): SessionProfile {
    const aggregates = this._computeAggregates();

    const profile: SessionProfile = {
      sessionId: this._sessionId,
      agentBuildId: this._agentBuildId,
      startedAt: this._startedAt,
      turns: this._turns,
      aggregates,
    };

    // Update the persistent baseline
    if (this._agentBuildId && this._turns.length > 0) {
      this._store.updateFromSession(this._agentBuildId, profile, this._toolInventory);
    }

    return profile;
  }

  /** Get all anomaly alerts from this session. */
  getAlerts(): readonly AnomalyAlert[] {
    return this._alerts;
  }

  /** Get LLM cache usage summary for the current session. */
  getCacheStats(): { totalInput: number; totalOutput: number; totalCacheRead: number; totalCacheWrite: number; hitRatio: number; turns: number } {
    let totalInput = 0, totalOutput = 0, totalCacheRead = 0, totalCacheWrite = 0;
    for (const t of this._turns) {
      totalInput += t.inputTokens;
      totalOutput += t.outputTokens;
      totalCacheRead += t.cacheReadTokens;
      totalCacheWrite += t.cacheWriteTokens;
    }
    return {
      totalInput, totalOutput, totalCacheRead, totalCacheWrite,
      hitRatio: totalInput > 0 ? totalCacheRead / totalInput : 0,
      turns: this._turns.length,
    };
  }

  /** Get current session profile (without finalizing). */
  getSessionProfile(): SessionProfile {
    return {
      sessionId: this._sessionId,
      agentBuildId: this._agentBuildId,
      startedAt: this._startedAt,
      turns: [...this._turns],
      aggregates: this._computeAggregates(),
    };
  }

  private _computeAggregates(): SessionAggregates {
    if (this._turns.length === 0) {
      return {
        dominantCategories: [],
        toolSequenceFingerprint: "",
        averageEntityDensity: 0,
        averageDirectiveVerbCount: 0,
        averageResponseLength: 0,
        averageLexicalOverlap: 0,
        turnCount: 0,
      };
    }

    // Category frequency
    const catFreq: Record<string, number> = {};
    const allTools = new Set<string>();
    let totalDensity = 0;
    let totalDirective = 0;
    let totalResponse = 0;
    let totalOverlap = 0;

    for (const turn of this._turns) {
      for (const [cat, count] of Object.entries(turn.entityCategoryCounts)) {
        catFreq[cat] = (catFreq[cat] ?? 0) + count;
      }
      for (const tool of turn.toolNames) allTools.add(tool);
      totalDensity += turn.entityDensityPer1k;
      totalDirective += turn.directiveVerbCount;
      totalResponse += turn.responseLength;
      totalOverlap += turn.lexicalOverlapWithPrevious;
    }

    const n = this._turns.length;
    const dominantCategories = Object.entries(catFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([cat]) => cat);

    const toolList = [...allTools].sort();
    const toolSequenceFingerprint = createHash("sha256")
      .update(toolList.join(","))
      .digest("hex")
      .slice(0, 12);

    return {
      dominantCategories,
      toolSequenceFingerprint,
      averageEntityDensity: totalDensity / n,
      averageDirectiveVerbCount: totalDirective / n,
      averageResponseLength: totalResponse / n,
      averageLexicalOverlap: totalOverlap / n,
      turnCount: n,
    };
  }
}

// ===================================================================
// Script/language detection (zero-dep, Unicode range based)
// ===================================================================

/** Detect the dominant script and non-Latin ratio of text. */
function detectScript(text: string): { script: string; nonLatinRatio: number } {
  let latin = 0;
  let cjk = 0;
  let cyrillic = 0;
  let arabic = 0;
  let devanagari = 0;
  let hangul = 0;
  let total = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20) continue; // control chars
    if (cp < 0x7F) { latin++; total++; continue; } // Basic Latin (ASCII)
    if (cp >= 0x00C0 && cp <= 0x024F) { latin++; total++; continue; } // Latin Extended
    if (cp >= 0x4E00 && cp <= 0x9FFF) { cjk++; total++; continue; } // CJK Unified
    if (cp >= 0x3040 && cp <= 0x30FF) { cjk++; total++; continue; } // Hiragana + Katakana
    if (cp >= 0x3400 && cp <= 0x4DBF) { cjk++; total++; continue; } // CJK Extension A
    if (cp >= 0x0400 && cp <= 0x04FF) { cyrillic++; total++; continue; } // Cyrillic
    if (cp >= 0x0600 && cp <= 0x06FF) { arabic++; total++; continue; } // Arabic
    if (cp >= 0x0900 && cp <= 0x097F) { devanagari++; total++; continue; } // Devanagari
    if (cp >= 0xAC00 && cp <= 0xD7AF) { hangul++; total++; continue; } // Hangul
    total++;
  }

  if (total === 0) return { script: "latin", nonLatinRatio: 0 };

  const nonLatin = total - latin;
  const nonLatinRatio = nonLatin / total;

  // Determine dominant script
  const counts: [string, number][] = [
    ["latin", latin],
    ["cjk", cjk],
    ["cyrillic", cyrillic],
    ["arabic", arabic],
    ["devanagari", devanagari],
    ["hangul", hangul],
  ];
  counts.sort((a, b) => b[1] - a[1]);
  const dominant = counts[0][1] > 0 ? counts[0][0] : "unknown";

  return { script: dominant, nonLatinRatio };
}

// ===================================================================
// Text analysis utilities
// ===================================================================

/** Extract lowercase words from text. */
function extractWords(text: string): string[] {
  return text.toLowerCase().match(/\b[a-z]{2,}\b/g) || [];
}

/** Compute word bigrams from a word array. */
function computeBigrams(words: string[]): Set<string> {
  const bigrams = new Set<string>();
  for (let i = 0; i < words.length - 1; i++) {
    bigrams.add(`${words[i]} ${words[i + 1]}`);
  }
  return bigrams;
}

/** Jaccard similarity between two sets. */
function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union > 0 ? intersection / union : 0;
}

/** Shannon entropy of a category count distribution. */
function shannonEntropy(counts: Record<string, number>): number {
  const values = Object.values(counts).filter((v) => v > 0);
  if (values.length === 0) return 0;

  const total = values.reduce((a, b) => a + b, 0);
  let entropy = 0;
  for (const v of values) {
    const p = v / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
