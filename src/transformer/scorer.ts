/**
 * Transformer anomaly scorer — inference-time bridge between the
 * transformer model and Shroud's security event system.
 *
 * Scores each tool call by measuring how surprised the model is.
 * High surprise = the agent is doing something it has never learned
 * to expect. Accumulates across a sliding window for session-level scores.
 *
 * Handles cold start: returns neutral scores until enough training
 * data accumulates, then auto-trains on first opportunity.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { MiniTransformer, DEFAULT_CONFIG, type TransformerConfig } from "./model.js";
import { ToolTokenizer, type TokenizerConfig } from "./tokenizer.js";
import { TransformerTrainer, DEFAULT_TRAINER_CONFIG, type TrainResult } from "./trainer.js";
import { crossEntropyLoss, softmax, l2Distance } from "./linalg.js";
import { AttackTraceStore, type AttackTrace } from "./contrastive.js";
import {
  ThreatHeadClassifier,
  type ThreatPrediction,
  type ThreatLabeledExample,
  LearnedThreatClass,
  THREAT_HEAD_NAMES,
} from "./threat-heads.js";
import { SelfLabelingFlywheel } from "./flywheel.js";
import type { SecurityEvent } from "../security-event.js";
import { ThreatClass } from "../security-event.js";
import type { VectorStore } from "../vector-store.js";

// ─── Types ───

export interface ScorerConfig {
  anomalyThreshold: number;     // 0.85 (surprise > this triggers event)
  windowSize: number;           // 10 (sliding window for session score)
  minSequenceLength: number;    // 3 (don't score until we have context)
  minSessionsToTrain: number;   // 30
  trainIntervalSessions: number; // 50
  intentAttentionThreshold: number; // 0.05 (below this = intent hijack)
}

export interface ToolPrediction {
  topK: Array<{ tool: string; prob: number }>;
  surprise: number;              // 1 - P(actual_next_tool)
  perplexity: number;           // exp(cross-entropy)
  sessionAnomalyScore: number;  // rolling average surprise over window
  embeddingShift: number;       // L2 distance between current and extended sequence embeddings
  /** Threat head prediction (Tier 4). Null if threat heads not initialized. */
  threatPrediction: ThreatPrediction | null;
  /** Average attention to position 0 (intent vector) across all heads/layers. */
  intentAttention: number;
  /** Per-head breakdown of attention to intent (numHeads × numLayers values). */
  intentAttentionPerHead: number[];
  /** Structured trust-zone override risk from hook-side prompt analysis. */
  trustZoneScore?: number;
  trustZoneContext?: TrustZoneContext | null;
}

export interface TrustZoneContext {
  privilegedTool: boolean;
  lowTrustText: boolean;
  matchedPatternCount: number;
  riskScore: number;
}

export interface TransformerStats {
  enabled: boolean;
  modelLoaded: boolean;
  vocabSize: number;
  totalParams: number;
  lastTrainedAt: number | null;
  trainingSessions: number;
  lastLoss: number | null;
  inferenceCount: number;
  avgInferenceMs: number;
  recentSurprises: number[];
  /** Recent intent attention scores (parallel to recentSurprises). */
  recentIntentAttention: number[];
  /** Min sessions needed before first training (for cold start progress). */
  minSessionsToTrain: number;
  /** Sessions accumulated since last training (progress counter). */
  sessionsSinceLastTrain: number;
  /** Number of attack traces in the contrastive store. */
  attackTraceCount: number;
  /** Threat head stats (Tier 4). */
  threatHeads: {
    enabled: boolean;
    paramCount: number;
    labelCount: number;
    reliabilityScores: number[];
  };
}

interface PersistedMeta {
  config: TransformerConfig;
  tokenizer: TokenizerConfig;
  lastTrainedAt: number;
  trainingSessions: number;
  lastLoss: number;
  sessionsSinceLastTrain: number;
}

export const DEFAULT_SCORER_CONFIG: ScorerConfig = {
  anomalyThreshold: 0.85,
  windowSize: 10,
  minSequenceLength: 3,
  minSessionsToTrain: 30,
  trainIntervalSessions: 50,
  intentAttentionThreshold: 0.05,
};

function predictionLikeIntentHijack(intentAttention: number, threshold: number): boolean {
  return threshold > 0 && intentAttention > 0 && intentAttention < threshold;
}

// ─── Scorer ───

export class TransformerScorer {
  private _model: MiniTransformer;
  private _tokenizer: ToolTokenizer;
  private _config: ScorerConfig;
  private _profileDir: string;
  private _modelLoaded = false;
  _attackTraceStore: AttackTraceStore;

  // Threat heads (Tier 4)
  _threatClassifier: ThreatHeadClassifier;
  _flywheel: SelfLabelingFlywheel;
  private _threatLabels: ThreatLabeledExample[] = [];
  private static readonly MAX_THREAT_LABELS = 1000;

  // Session state
  private _surpriseWindow: number[] = [];
  private _intentAttentionWindow: number[] = [];

  // Stats
  private _inferenceCount = 0;
  private _totalInferenceMs = 0;
  private _lastTrainedAt: number | null = null;
  private _trainingSessions = 0;
  private _lastLoss: number | null = null;
  private _sessionsSinceLastTrain = 0;

  constructor(
    profileDir: string,
    config: ScorerConfig = DEFAULT_SCORER_CONFIG,
  ) {
    this._profileDir = profileDir.startsWith("~")
      ? join(process.env.HOME || "/tmp", profileDir.slice(1))
      : profileDir;
    this._config = config;
    this._model = new MiniTransformer(DEFAULT_CONFIG);
    this._tokenizer = new ToolTokenizer();
    this._attackTraceStore = new AttackTraceStore(this._profileDir);
    this._attackTraceStore.load();
    this._threatClassifier = new ThreatHeadClassifier();
    this._threatClassifier.initWeights();
    this._flywheel = new SelfLabelingFlywheel();
    this._modelLoaded = this._loadModel();
  }

  /** Record an attack trace for contrastive training. */
  recordAttackTrace(trace: AttackTrace): void {
    this._attackTraceStore.add(trace);
  }

  /** Score a tool call given the sequence so far.
   *  @param intentVec — 256-dim TF-IDF embedding of the user's message (from DriftDetector).
   *    When provided, the model conditions predictions on user intent — "read secrets.env"
   *    gets different surprise depending on whether the user asked about secrets vs bugs. */
  scoreToolCall(
    currentSequence: string[],
    nextTool: string,
    intentVec?: Float64Array | null,
    trustZoneContext?: TrustZoneContext | null,
  ): ToolPrediction {
    const baseTrustZoneScore = trustZoneContext?.riskScore || 0;
    if (!this._modelLoaded || currentSequence.length < this._config.minSequenceLength) {
      return {
        topK: [],
        surprise: 0,
        perplexity: 1,
        sessionAnomalyScore: 0,
        embeddingShift: 0,
        threatPrediction: null,
        intentAttention: 0,
        intentAttentionPerHead: [],
        trustZoneScore: baseTrustZoneScore,
        trustZoneContext: trustZoneContext || null,
      };
    }

    const start = Date.now();

    // Ensure tool is in vocabulary (returns UNK if vocab full)
    this._tokenizer.addTool(nextTool);
    for (const t of currentSequence) this._tokenizer.addTool(t);

    // Encode sequence and predict
    const inputIds = this._tokenizer.encodeSequence(currentSequence);

    // Truncate if too long
    if (inputIds.length > this._model.config.maxSeqLen) {
      inputIds.splice(0, inputIds.length - this._model.config.maxSeqLen);
    }

    const cache = this._model.forwardFull(inputIds, intentVec);
    const probs = softmax(cache.logits, this._model.config.vocabSize);
    const nextId = this._tokenizer.encode(nextTool);
    const nextProb = probs[nextId] || 0;
    const surprise = 1 - nextProb;

    // Cross-entropy for perplexity
    const ce = -Math.log(Math.max(nextProb, 1e-12));
    const perplexity = Math.exp(ce);

    // Top-K predictions
    const topK: Array<{ tool: string; prob: number }> = [];
    const indices = Array.from({ length: probs.length }, (_, i) => i);
    indices.sort((a, b) => probs[b] - probs[a]);
    for (let i = 0; i < Math.min(5, indices.length); i++) {
      if (probs[indices[i]] > 0.01) {
        topK.push({
          tool: this._tokenizer.decode(indices[i]),
          prob: probs[indices[i]],
        });
      }
    }

    // Compute embedding shift: L2 distance between current sequence embedding
    // and extended sequence embedding (with nextTool appended)
    let embeddingShift = 0;
    try {
      const currentEmb = this._model.getEmbedding(inputIds, intentVec);
      const extendedIds = [...inputIds, nextId];
      if (extendedIds.length <= this._model.config.maxSeqLen) {
        const extendedEmb = this._model.getEmbedding(extendedIds, intentVec);
        embeddingShift = l2Distance(currentEmb, extendedEmb, this._model.config.hiddenDim);
      }
    } catch {
      // Best-effort — don't let embedding computation break scoring
    }

    // Extract intent attention from forward cache: average across all heads/layers
    const intentAttentionPerHead = Array.from(cache.intentAttention);
    const intentAttention = intentAttentionPerHead.length > 0
      ? intentAttentionPerHead.reduce((a, b) => a + b, 0) / intentAttentionPerHead.length
      : 0;

    // Update sliding windows
    this._surpriseWindow.push(surprise);
    if (this._surpriseWindow.length > this._config.windowSize) {
      this._surpriseWindow.shift();
    }
    this._intentAttentionWindow.push(intentAttention);
    if (this._intentAttentionWindow.length > this._config.windowSize) {
      this._intentAttentionWindow.shift();
    }

    const sessionAnomalyScore = this._surpriseWindow.reduce((a, b) => a + b, 0)
      / this._surpriseWindow.length;

    // Threat head classification (Tier 4)
    let threatPrediction: ThreatPrediction | null = null;
    try {
      threatPrediction = this._threatClassifier.forward(
        cache.finalLnOut,
        cache.headAttentionEntropy,
      );
    } catch {
      // Best-effort — don't break scoring if threat heads fail
    }

    // Stats
    this._inferenceCount++;
    this._totalInferenceMs += Date.now() - start;

    const trustZoneScore = trustZoneContext
      ? Math.min(
          1,
          trustZoneContext.riskScore
            + (predictionLikeIntentHijack(intentAttention, this._config.intentAttentionThreshold) ? 0.15 : 0)
            + (surprise > this._config.anomalyThreshold ? 0.1 : 0),
        )
      : 0;

    return {
      topK,
      surprise,
      perplexity,
      sessionAnomalyScore,
      embeddingShift,
      threatPrediction,
      intentAttention,
      intentAttentionPerHead,
      trustZoneScore,
      trustZoneContext: trustZoneContext || null,
    };
  }

  /** Check if a prediction triggers a security event.
   *  Returns up to 2 events: one for surprise anomaly, one for threat head classification. */
  checkAnomaly(
    prediction: ToolPrediction,
    nextTool: string,
    agentLabel?: string,
  ): SecurityEvent | null {
    if (prediction.trustZoneContext?.privilegedTool && (prediction.trustZoneScore ?? 0) >= 0.8) {
      return {
        timestamp: Date.now(),
        eventType: "anomaly_detected",
        direction: "request",
        threatClass: ThreatClass.INSTRUCTION_OVERRIDE,
        signatureId: "transformer_trust_zone_override",
        severity: (prediction.trustZoneScore ?? 0) >= 0.9 ? "high" : "medium",
        matchedText: `Tool "${nextTool}" trust_zone_score=${(prediction.trustZoneScore ?? 0).toFixed(3)}`,
        matchStart: 0,
        matchEnd: 0,
        textLength: 0,
        action: "flagged",
        description: `Transformer trust-zone head: low-trust override pressure reached ${nextTool} (score=${(prediction.trustZoneScore ?? 0).toFixed(3)}, matched_patterns=${prediction.trustZoneContext.matchedPatternCount}).`,
        agentLabel,
      };
    }

    // Check threat head classification first
    if (prediction.threatPrediction) {
      const tp = prediction.threatPrediction;
      for (const headPred of tp.heads) {
        const hostile = headPred.distribution[LearnedThreatClass.HOSTILE];
        const suspicious = headPred.distribution[LearnedThreatClass.SUSPICIOUS];

        if (hostile > 0.7 || suspicious > 0.6) {
          const threatClassMap: Record<string, ThreatClass> = {
            exfiltration: ThreatClass.EXFILTRATION_LEARNED,
            privilege_escalation: ThreatClass.PRIVILEGE_ESCALATION_LEARNED,
            reconnaissance: ThreatClass.RECONNAISSANCE_LEARNED,
          };
          const severity = hostile > 0.7 ? "high" as const : "medium" as const;
          const threatClass = threatClassMap[headPred.name] || ThreatClass.TOOL_SEQUENCE_ANOMALY;

          return {
            timestamp: Date.now(),
            eventType: "anomaly_detected",
            direction: "request",
            threatClass,
            signatureId: `transformer_threat_${headPred.name}`,
            severity,
            matchedText: `Tool "${nextTool}" classified as ${headPred.predicted === LearnedThreatClass.HOSTILE ? "HOSTILE" : "SUSPICIOUS"} by ${headPred.name} head (P=${(hostile > 0.7 ? hostile : suspicious).toFixed(3)})`,
            matchStart: 0,
            matchEnd: 0,
            textLength: 0,
            action: "flagged",
            description: `Threat head "${headPred.name}": tool "${nextTool}" classified as ${headPred.predicted === LearnedThreatClass.HOSTILE ? "HOSTILE" : "SUSPICIOUS"} (hostile=${hostile.toFixed(3)}, suspicious=${suspicious.toFixed(3)}, threat_score=${tp.threatScore.toFixed(3)}).`,
            agentLabel,
          };
        }
      }
    }

    // Check intent attention dropout: if heads have stopped attending to position 0 (intent),
    // the agent may have been hijacked away from the user's request.
    // Only fires when intentAttentionPerHead is populated (model produced intent attention)
    // and the average drops below threshold.
    if (prediction.intentAttentionPerHead && prediction.intentAttentionPerHead.length > 0 &&
        prediction.intentAttention < this._config.intentAttentionThreshold) {
      const perHead = prediction.intentAttentionPerHead
        .map((v, i) => `h${i}=${v.toFixed(4)}`)
        .join(", ");
      return {
        timestamp: Date.now(),
        eventType: "anomaly_detected",
        direction: "request",
        threatClass: ThreatClass.INTENT_HIJACK,
        signatureId: "transformer_intent_hijack",
        severity: prediction.intentAttention < 0.01 ? "high" as const : "medium" as const,
        matchedText: `Tool "${nextTool}" intent_attention=${prediction.intentAttention.toFixed(4)}, threshold=${this._config.intentAttentionThreshold}`,
        matchStart: 0,
        matchEnd: 0,
        textLength: 0,
        action: "flagged",
        description: `Attention to user intent dropped to ${prediction.intentAttention.toFixed(4)} (threshold=${this._config.intentAttentionThreshold}). Per-head: [${perHead}]. Agent may be hijacked away from original request.`,
        agentLabel,
      };
    }

    if (prediction.surprise < this._config.anomalyThreshold) return null;

    const severity = prediction.surprise > 0.95 ? "high"
      : prediction.surprise > 0.9 ? "medium"
      : "low";

    const topExpected = prediction.topK.slice(0, 3)
      .map(k => `${k.tool}(${(k.prob * 100).toFixed(0)}%)`)
      .join(", ");

    return {
      timestamp: Date.now(),
      eventType: "anomaly_detected",
      direction: "request",
      threatClass: ThreatClass.TOOL_SEQUENCE_ANOMALY,
      signatureId: "transformer_surprise",
      severity,
      matchedText: `Tool "${nextTool}" surprise=${prediction.surprise.toFixed(3)}, expected: ${topExpected}`,
      matchStart: 0,
      matchEnd: 0,
      textLength: 0,
      action: "flagged",
      description: `Transformer next-tool predictor: "${nextTool}" was unexpected (surprise=${prediction.surprise.toFixed(3)}, session=${prediction.sessionAnomalyScore.toFixed(3)}). Model expected: ${topExpected}.`,
      agentLabel,
    };
  }

  /** Reset session state (call on new session/turn). */
  resetSession(): void {
    this._surpriseWindow = [];
    this._intentAttentionWindow = [];
  }

  /** Check if we should retrain, and do it if so. Returns result or null. */
  async maybeRetrain(vectorStore: VectorStore): Promise<TrainResult | null> {
    this._sessionsSinceLastTrain++;

    const workflows = vectorStore.getWorkflows();
    const totalSessions = workflows.length;

    // Don't train until we have enough data
    if (totalSessions < this._config.minSessionsToTrain) return null;

    // Don't retrain too frequently
    if (this._modelLoaded && this._sessionsSinceLastTrain < this._config.trainIntervalSessions) {
      return null;
    }

    // Extract sequences
    const sequences = workflows
      .filter(w => w.sequence.length >= 2)
      .map(w => w.sequence);

    if (sequences.length < this._config.minSessionsToTrain) return null;

    // Ensure all tools are in vocabulary
    for (const seq of sequences) {
      for (const tool of seq) this._tokenizer.addTool(tool);
    }

    // Initialize weights if first training
    if (!this._modelLoaded) {
      this._model.initWeights();
    }

    // Train (pass attack traces for contrastive learning + threat labels for Tier 4)
    const trainer = new TransformerTrainer(this._model, this._tokenizer);
    const traces = this._attackTraceStore.getAll();
    const result = await trainer.trainOnSequences(
      sequences,
      undefined,
      traces.length > 0 ? traces : undefined,
      this._threatLabels.length > 0 ? this._threatClassifier : undefined,
      this._threatLabels.length > 0 ? this._threatLabels : undefined,
    );

    // Update state
    this._modelLoaded = true;
    this._lastTrainedAt = Date.now();
    this._trainingSessions = totalSessions;
    this._lastLoss = result.finalLoss;
    this._sessionsSinceLastTrain = 0;

    // Persist
    this._saveModel();

    return result;
  }

  /** Get stats for dashboard. */
  getStats(): TransformerStats {
    return {
      enabled: true,
      modelLoaded: this._modelLoaded,
      vocabSize: this._tokenizer.vocabSize(),
      totalParams: this._model.paramCount(),
      lastTrainedAt: this._lastTrainedAt,
      trainingSessions: this._trainingSessions,
      lastLoss: this._lastLoss,
      inferenceCount: this._inferenceCount,
      avgInferenceMs: this._inferenceCount > 0
        ? this._totalInferenceMs / this._inferenceCount
        : 0,
      recentSurprises: [...this._surpriseWindow],
      recentIntentAttention: [...this._intentAttentionWindow],
      minSessionsToTrain: this._config.minSessionsToTrain,
      sessionsSinceLastTrain: this._sessionsSinceLastTrain,
      attackTraceCount: this._attackTraceStore.count(),
      threatHeads: {
        enabled: true,
        paramCount: this._threatClassifier.paramCount(),
        labelCount: this._threatLabels.length,
        reliabilityScores: Array.from(this._threatClassifier.weights.reliability),
      },
    };
  }

  /** Record a threat-labeled example for training. Ring buffer, max 1000. */
  recordThreatLabel(example: ThreatLabeledExample): void {
    this._threatLabels.push(example);
    if (this._threatLabels.length > TransformerScorer.MAX_THREAT_LABELS) {
      this._threatLabels.splice(0, this._threatLabels.length - TransformerScorer.MAX_THREAT_LABELS);
    }
  }

  /** Convenience: process a honeypot trigger through the flywheel. */
  onHoneypotTrigger(
    tokenType: string,
    sessionSequence: string[],
    injectionIdx: number,
    intentVec?: Float64Array | null,
  ): void {
    const result = this._flywheel.onHoneypotTrigger(tokenType, sessionSequence, injectionIdx, intentVec);
    this.recordAttackTrace(result.trace);
    for (const label of result.labels) this.recordThreatLabel(label);
  }

  /** Convenience: process a phantom tool trigger through the flywheel. */
  onPhantomTrigger(
    trapType: string,
    sessionSequence: string[],
    intentVec?: Float64Array | null,
  ): void {
    const result = this._flywheel.onPhantomTrigger(trapType, sessionSequence, intentVec);
    this.recordAttackTrace(result.trace);
    for (const label of result.labels) this.recordThreatLabel(label);
  }

  /** Convenience: process a shadow execution block through the flywheel. */
  onShadowBlock(
    verdictReason: string,
    sessionSequence: string[],
    shadowSteps: string[],
    intentVec?: Float64Array | null,
  ): void {
    const result = this._flywheel.onShadowBlock(verdictReason, sessionSequence, shadowSteps, intentVec);
    this.recordAttackTrace(result.trace);
    for (const label of result.labels) this.recordThreatLabel(label);
  }

  /** Load model from disk. Returns true if loaded successfully. */
  private _loadModel(): boolean {
    try {
      const metaPath = join(this._profileDir, "transformer-config.json");
      const weightsPath = join(this._profileDir, "transformer-weights.bin");

      if (!existsSync(metaPath) || !existsSync(weightsPath)) return false;

      const meta: PersistedMeta = JSON.parse(readFileSync(metaPath, "utf-8"));
      this._tokenizer = ToolTokenizer.fromJSON(meta.tokenizer);
      this._model = new MiniTransformer(meta.config);
      this._model.deserializeWeights(readFileSync(weightsPath));
      this._lastTrainedAt = meta.lastTrainedAt;
      this._trainingSessions = meta.trainingSessions;
      this._lastLoss = meta.lastLoss;
      this._sessionsSinceLastTrain = meta.sessionsSinceLastTrain || 0;

      // Load threat head weights if they exist (backward compat: fresh init if not found)
      try {
        const threatPath = join(this._profileDir, "threat-heads-weights.bin");
        if (existsSync(threatPath)) {
          const threatBuf = readFileSync(threatPath);
          const threatData = new Float64Array(threatBuf.buffer, threatBuf.byteOffset, threatBuf.byteLength / 8);
          this._threatClassifier.deserialize(threatData);
        }
      } catch {
        // Backward compat: old models without threat heads get fresh init
      }

      return true;
    } catch {
      return false;
    }
  }

  /** Save model to disk. Only persists if model has been trained. */
  _saveModel(): void {
    if (!this._modelLoaded) return;
    try {
      mkdirSync(this._profileDir, { recursive: true });

      const meta: PersistedMeta = {
        config: this._model.config,
        tokenizer: this._tokenizer.toJSON(),
        lastTrainedAt: this._lastTrainedAt || Date.now(),
        trainingSessions: this._trainingSessions,
        lastLoss: this._lastLoss || 0,
        sessionsSinceLastTrain: this._sessionsSinceLastTrain,
      };

      writeFileSync(
        join(this._profileDir, "transformer-config.json"),
        JSON.stringify(meta, null, 2),
        "utf-8",
      );

      writeFileSync(
        join(this._profileDir, "transformer-weights.bin"),
        this._model.serializeWeights(),
      );

      // Persist attack traces alongside model
      this._attackTraceStore.save();

      // Persist threat head weights
      try {
        const threatData = this._threatClassifier.serialize();
        const threatBuf = Buffer.from(threatData.buffer, threatData.byteOffset, threatData.byteLength);
        writeFileSync(join(this._profileDir, "threat-heads-weights.bin"), threatBuf);
      } catch {
        // Best-effort
      }
    } catch {
      // Best-effort persistence
    }
  }

  /** Static factory that handles cold start. */
  static create(
    profileDir: string,
    config: ScorerConfig = DEFAULT_SCORER_CONFIG,
    vectorStore?: VectorStore,
  ): TransformerScorer {
    const scorer = new TransformerScorer(profileDir, config);

    // Cold start: no weights on disk → seed pretrain from testbed
    if (!scorer._modelLoaded) {
      try {
        const { seedPretrain } = require("./seed-pretrain.js") as { seedPretrain: (dir: string) => Promise<any> };
        seedPretrain(profileDir).then(() => {
          // Reload after seed pretrain completes
          scorer._loadModel();
        }).catch(() => {});
      } catch {
        // seed-pretrain not available (e.g. minimal install) — continue without
      }
    }

    // If we have a vector store and enough data but no model, try initial training
    if (!scorer._modelLoaded && vectorStore) {
      const workflows = vectorStore.getWorkflows();
      if (workflows.length >= config.minSessionsToTrain) {
        scorer.maybeRetrain(vectorStore);
      }
    }

    return scorer;
  }
}
