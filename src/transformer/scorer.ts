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
import { crossEntropyLoss, softmax } from "./linalg.js";
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
}

export interface ToolPrediction {
  topK: Array<{ tool: string; prob: number }>;
  surprise: number;              // 1 - P(actual_next_tool)
  perplexity: number;           // exp(cross-entropy)
  sessionAnomalyScore: number;  // rolling average surprise over window
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
};

// ─── Scorer ───

export class TransformerScorer {
  private _model: MiniTransformer;
  private _tokenizer: ToolTokenizer;
  private _config: ScorerConfig;
  private _profileDir: string;
  private _modelLoaded = false;

  // Session state
  private _surpriseWindow: number[] = [];

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
    this._modelLoaded = this._loadModel();
  }

  /** Score a tool call given the sequence so far. */
  scoreToolCall(currentSequence: string[], nextTool: string): ToolPrediction {
    if (!this._modelLoaded || currentSequence.length < this._config.minSequenceLength) {
      return {
        topK: [],
        surprise: 0,
        perplexity: 1,
        sessionAnomalyScore: 0,
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

    const probs = this._model.predict(inputIds);
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

    // Update sliding window
    this._surpriseWindow.push(surprise);
    if (this._surpriseWindow.length > this._config.windowSize) {
      this._surpriseWindow.shift();
    }

    const sessionAnomalyScore = this._surpriseWindow.reduce((a, b) => a + b, 0)
      / this._surpriseWindow.length;

    // Stats
    this._inferenceCount++;
    this._totalInferenceMs += Date.now() - start;

    return { topK, surprise, perplexity, sessionAnomalyScore };
  }

  /** Check if a prediction triggers a security event. */
  checkAnomaly(
    prediction: ToolPrediction,
    nextTool: string,
    agentLabel?: string,
  ): SecurityEvent | null {
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
  }

  /** Check if we should retrain, and do it if so. Returns result or null. */
  maybeRetrain(vectorStore: VectorStore): TrainResult | null {
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

    // Train
    const trainer = new TransformerTrainer(this._model, this._tokenizer);
    const result = trainer.trainOnSequences(sequences);

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
    };
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

      return true;
    } catch {
      return false;
    }
  }

  /** Save model to disk. */
  _saveModel(): void {
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
